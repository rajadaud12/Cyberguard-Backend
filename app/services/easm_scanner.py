"""
CyberGuard -- EASM Scanner Service
Real internet-facing asset discovery and probing.

For each domain/CIDR in scan_scopes:
  - HTTP/HTTPS probe: status code, tech stack from headers, redirect chain
  - Security headers grade: CSP, HSTS, X-Frame-Options, etc.
  - TLS certificate: issuer, valid_from, valid_to, SANs, expiry
  - Common port scan: 21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017
  - Findings: auto-generate for expired certs, bad headers, risky ports

Results are upserted into easm_assets, easm_ports, easm_certificates, findings.
"""
import asyncio
import ipaddress
import logging
import socket
import ssl
import uuid
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
import warnings
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=UserWarning)
    from Wappalyzer import Wappalyzer, WebPage

_WAPPALYZER = None
def _get_wappalyzer():
    global _WAPPALYZER
    if _WAPPALYZER is None:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            _WAPPALYZER = Wappalyzer.latest()
    return _WAPPALYZER
import re
from bs4 import BeautifulSoup

import httpx
from cryptography import x509
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_tenant_db
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.scope import ScanScope
from app.services.cve_service import CveLookupService
from app.services.verification_engine import NucleiVerificationEngine

logger = logging.getLogger(__name__)

# ── Concurrency guards ─────────────────────────────────────────────────────────
# Limits the total number of hosts scanned concurrently across ALL tenants.
# Kept LOW (3) to prevent socket/FD/memory exhaustion on 512MB Render instances.
_GLOBAL_SCAN_SEM = asyncio.Semaphore(1)

# Tracks tenant locks to queue background scans sequentially.
# Prevents duplicate scans overlapping, but allows them to queue.
_TENANT_LOCKS: dict[str, asyncio.Lock] = {}

def _get_tenant_lock(tenant_id: str) -> asyncio.Lock:
    if tenant_id not in _TENANT_LOCKS:
        _TENANT_LOCKS[tenant_id] = asyncio.Lock()
    return _TENANT_LOCKS[tenant_id]

# ── Shared HTTP client ─────────────────────────────────────────────────────────
# Re-used across all probe functions. Connection limits kept low for 512MB servers.
_HTTP_CLIENT = httpx.AsyncClient(
    follow_redirects=True,
    timeout=5.0,
    verify=False,
    limits=httpx.Limits(
        max_connections=20,            # low cap for 512MB server
        max_keepalive_connections=5,   # minimal keep-alive pool
        keepalive_expiry=5,            # close idle conns quickly
    ),
    headers={"User-Agent": "CyberGuard-EASM/1.0"},
)

# ── Port scan targets ──────────────────────────────────────────────────────────
COMMON_PORTS = [
    (21,    "FTP",        "high"),
    (22,    "SSH",        "medium"),
    (23,    "Telnet",     "critical"),
    (25,    "SMTP",       "medium"),
    (80,    "HTTP",       "info"),
    (443,   "HTTPS",      "info"),
    (3000,  "HTTP-Alt",   "medium"),
    (4000,  "HTTP-Alt",   "medium"),
    (3306,  "MySQL",      "critical"),
    (5432,  "PostgreSQL", "critical"),
    (6379,  "Redis",      "critical"),
    (8000,  "HTTP-Alt",   "medium"),
    (8081,  "HTTP-Alt",   "medium"),
    (8080,  "HTTP-Alt",   "medium"),
    (8443,  "HTTPS-Alt",  "low"),
    (27017, "MongoDB",    "critical"),
]

# Ports that are risky when publicly internet-reachable
RISKY_PORTS = {3306, 5432, 6379, 27017, 23, 21}
# Ports risky only if no auth banner found
CONDITIONALLY_RISKY = {22, 25}

# ── Security header grade weights ──────────────────────────────────────────────
SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _grade_security_headers(headers: dict) -> str:
    """
    Grade security headers A-F.
    A = 5-6 headers present, F = 0-1
    """
    h_lower = {k.lower(): v for k, v in headers.items()}
    present = sum(1 for h in SEC_HEADERS if h in h_lower)
    if present >= 5:
        return "A"
    if present == 4:
        return "B"
    if present == 3:
        return "C"
    if present == 2:
        return "D"
    return "F"


def _detect_tech_stack(url: str, headers: dict, html: str) -> list[dict]:
    """
    Detect tech stack using Wappalyzer + robust multi-layer manual fallbacks.
    Handles JS-heavy SPAs, PHP frameworks, CDN-served sites, etc.
    Returns: [{"name": "Nginx", "version": "1.18.0"}, ...]
    """
    result = []
    try:
        wapp = _get_wappalyzer()
        page = WebPage(url, html=html, headers=headers)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            analysis = wapp.analyze_with_versions_and_categories(page)
        for tech_name, data in analysis.items():
            versions = data.get("versions", [])
            v = versions[0] if versions else ""
            result.append({"name": tech_name, "version": v})
    except Exception as e:
        logger.warning(f"Wappalyzer failed for {url}: {e}")

    existing_names = {t["name"].lower() for t in result}
    h_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html.lower()

    def _add(name: str, version: str = ""):
        if name.lower() not in existing_names:
            result.append({"name": name, "version": version})
            existing_names.add(name.lower())

    # ── Layer 1: Response Headers ──────────────────────────────────────────────
    server = h_lower.get("server", "")
    x_powered = h_lower.get("x-powered-by", "")
    x_generator = h_lower.get("x-generator", "")
    via = h_lower.get("via", "")
    cf_ray = h_lower.get("cf-ray", "")

    if "nginx" in server:
        v = re.search(r"nginx/([\d.]+)", server)
        _add("Nginx", v.group(1) if v else "")
    if "apache" in server:
        v = re.search(r"apache/([\d.]+)", server, re.IGNORECASE)
        _add("Apache HTTP Server", v.group(1) if v else "")
    if "litespeed" in server.lower():
        _add("LiteSpeed")
    if "openresty" in server.lower():
        _add("OpenResty")
    if "caddy" in server.lower():
        _add("Caddy")
    if "iis" in server.lower():
        v = re.search(r"iis/([\d.]+)", server, re.IGNORECASE)
        _add("IIS", v.group(1) if v else "")

    if "php" in x_powered.lower():
        v = re.search(r"php/([\d.]+)", x_powered, re.IGNORECASE)
        _add("PHP", v.group(1) if v else "")
    if "laravel" in x_powered.lower():
        _add("Laravel")
    if "express" in x_powered.lower():
        _add("Express")
    if "asp.net" in x_powered.lower():
        v = re.search(r"asp\.net mvc ([\d.]+)", x_powered, re.IGNORECASE)
        _add("ASP.NET MVC", v.group(1) if v else "")
        _add("ASP.NET")

    if cf_ray or "cloudflare" in server.lower() or "cloudflare" in via.lower():
        _add("Cloudflare")
    if "varnish" in via.lower() or "varnish" in server.lower():
        _add("Varnish")
    if "fastly" in via.lower() or "fastly" in server.lower():
        _add("Fastly")
    if "akamai" in via.lower():
        _add("Akamai")

    if x_generator:
        if "wordpress" in x_generator.lower():
            _add("WordPress")
        elif "drupal" in x_generator.lower():
            _add("Drupal")

    # ── Layer 2: HTML Meta Tags & Generator Tags ───────────────────────────────
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if gen_match:
        gen = gen_match.group(1).lower()
        if "wordpress" in gen:
            v = re.search(r"wordpress ([\d.]+)", gen_match.group(1), re.IGNORECASE)
            _add("WordPress", v.group(1) if v else "")
        elif "joomla" in gen:
            _add("Joomla")
        elif "drupal" in gen:
            _add("Drupal")
        elif "wix" in gen:
            _add("Wix")
        elif "shopify" in gen:
            _add("Shopify")
        elif "squarespace" in gen:
            _add("Squarespace")
        elif "hugo" in gen:
            _add("Hugo")
        elif "jekyll" in gen:
            _add("Jekyll")
        elif "gatsby" in gen:
            _add("Gatsby")

    # ── Layer 3: HTML Body Patterns ────────────────────────────────────────────
    # Next.js
    if "next.js" not in existing_names:
        if "_next/static" in html or "__NEXT_DATA__" in html or "self.__next_f" in html:
            _add("Next.js")

    # React
    if "react" not in existing_names:
        if "next.js" in existing_names or "data-reactroot" in html or "__REACT_DEVTOOLS_GLOBAL_HOOK__" in html or "react-dom" in html_lower:
            _add("React")

    # Vue.js
    if "vue.js" not in existing_names and "vue" not in existing_names:
        if "data-v-" in html or "__vue_app__" in html or "vue.runtime.esm" in html_lower or "createapp" in html_lower:
            v = re.search(r"vue@([\d.]+)", html)
            _add("Vue.js", v.group(1) if v else "")

    # Alpine.js
    if "alpine.js" not in existing_names:
        if "x-data=" in html or "x-bind:" in html or "@click=" in html or "alpine" in html_lower and "cdn" in html_lower:
            _add("Alpine.js")

    # Laravel (server-side rendered)
    if "laravel" not in existing_names:
        if "laravel_session" in html_lower or "laravel" in html_lower or "_token" in html and "csrf" in html_lower:
            _add("Laravel")

    # Livewire (Laravel component)
    if "livewire" not in existing_names:
        if "wire:id=" in html or "livewire/livewire.js" in html_lower or "livewire" in html_lower:
            _add("Livewire")

    # Inertia.js (InvoiceNinja uses this)
    if "inertia" not in existing_names:
        if 'id="app"' in html and 'data-page=' in html:
            _add("Inertia.js")
        elif "inertia" in html_lower and "component" in html_lower:
            _add("Inertia.js")

    # Tailwind CSS
    if "tailwind css" not in existing_names and "tailwindcss" not in existing_names:
        if "tailwindcss" in html_lower or "tw-" in html or re.search(r'class="[^"]*(?:flex|grid|px-|py-|text-|bg-|font-)[^"]*"', html):
            _add("Tailwind CSS")

    # Bootstrap
    if "bootstrap" not in existing_names:
        if "bootstrap" in html_lower and ("btn-" in html or "col-md-" in html or "navbar" in html_lower):
            v = re.search(r"bootstrap@([\d.]+)", html) or re.search(r"bootstrap/([\d.]+)/", html)
            _add("Bootstrap", v.group(1) if v else "")

    # jQuery
    if "jquery" not in existing_names:
        v = re.search(r"jquery[.-]([\d.]+)", html_lower) or re.search(r"jquery/([\d.]+)/", html_lower)
        if "jquery" in html_lower:
            _add("jQuery", v.group(1) if v else "")

    # Angular
    if "angular" not in existing_names:
        if "ng-version=" in html or "_nghost-" in html or "ng-app=" in html:
            v = re.search(r"ng-version=[\"']([\d.]+)", html)
            _add("Angular", v.group(1) if v else "")

    # Svelte
    if "svelte" not in existing_names:
        if "svelte" in html_lower and ("__svelte" in html or "svelte-" in html):
            _add("Svelte")

    # WordPress specific patterns
    if "wordpress" not in existing_names:
        if "wp-content/" in html or "wp-includes/" in html or "wp-json" in html_lower:
            _add("WordPress")
        if "wordpress" in existing_names and "woocommerce" not in existing_names:
            if "woocommerce" in html_lower:
                _add("WooCommerce")

    # Shopify
    if "shopify" not in existing_names:
        if "cdn.shopify.com" in html_lower or "shopify.com/s/files" in html_lower:
            _add("Shopify")

    # Webflow
    if "webflow" not in existing_names:
        if "webflow.com" in html_lower or 'data-wf-' in html:
            _add("Webflow")

    # Nuxt.js
    if "nuxt.js" not in existing_names and "nuxt" not in existing_names:
        if "__nuxt" in html or "_nuxt/" in html or "nuxt" in html_lower:
            _add("Nuxt.js")

    # Gatsby
    if "gatsby" not in existing_names:
        if "gatsby-" in html_lower or "___gatsby" in html:
            _add("Gatsby")

    # Astro
    if "astro" not in existing_names:
        if "astro-" in html_lower or "<astro-" in html_lower:
            _add("Astro")

    # Ruby on Rails
    if "ruby on rails" not in existing_names:
        if "rails" in html_lower and ("authenticity_token" in html_lower or "data-turbo" in html):
            _add("Ruby on Rails")

    # Django
    if "django" not in existing_names:
        if "csrfmiddlewaretoken" in html_lower or "django" in html_lower:
            _add("Django")

    # ASP.NET
    if "asp.net" not in existing_names:
        if "__viewstate" in html_lower or "asp.net" in html_lower:
            _add("ASP.NET")

    return result

async def _calculate_cve_data(tech_stack: list[dict]) -> list[dict]:
    """Fetch actual CVE data from CveLookupService."""
    cve_service = CveLookupService()
    all_cves = []
    for tech in tech_stack:
        cves = await cve_service.get_cves_for_tech(tech["name"], tech.get("version", ""))
        all_cves.extend(cves)
    await cve_service.close()
    return all_cves

async def _test_catch_all(base_url: str) -> bool:
    """
    Test if the server is a catch-all by requesting a random non-existent path.
    """
    random_path = f"cx-{uuid.uuid4().hex[:8]}-random"
    test_url = f"{base_url.rstrip('/')}/{random_path}"
    try:
        resp = await _HTTP_CLIENT.get(test_url)
        return resp.status_code == 200
    except Exception as e:
        logger.debug(f"Catch-all probe {test_url}: {e}")
        return False


# Load Signatures Dynamically
_SIGNATURES_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "easm_signatures.json")
try:
    with open(_SIGNATURES_FILE, "r") as f:
        _sigs = json.load(f)
        SENSITIVE_PATH_SIGNATURES = _sigs.get("sensitive_paths", [])
        SUSPICIOUS_PATTERNS = []
        for p in _sigs.get("suspicious_patterns", []):
            SUSPICIOUS_PATTERNS.append({
                "regex": re.compile(p["regex"], re.IGNORECASE),
                "severity": p["severity"],
                "type": p["type"]
            })
        FINGERPRINTS = []
        for fp in _sigs.get("fingerprints", []):
            FINGERPRINTS.append({
                "regex": re.compile(fp["regex"], re.IGNORECASE),
                "app": fp["app"],
                "severity": fp["severity"],
                "type": fp["type"]
            })
except Exception as e:
    logger.error(f"Failed to load signatures: {e}")
    SENSITIVE_PATH_SIGNATURES = []
    SUSPICIOUS_PATTERNS = []
    FINGERPRINTS = []


async def _crawl_links(base_url: str) -> set[str]:
    """Crawl homepage, robots.txt, and sitemap.xml for paths."""
    paths = set()
    try:
        # Crawl root
        resp = await _HTTP_CLIENT.get(base_url)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.content, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/"):
                    paths.add(href)
            # Find fetch calls in inline scripts
            for script in soup.find_all("script"):
                if script.string:
                    for match in re.findall(r'fetch\(([\'"])(.*?)\1\)', script.string):
                        if match[1].startswith("/"):
                            paths.add(match[1])
                            
        # Crawl robots.txt
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        resp = await _HTTP_CLIENT.get(robots_url)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if path and path.startswith("/"):
                            paths.add(path)
                            
        # Crawl sitemap.xml
        sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"
        resp = await _HTTP_CLIENT.get(sitemap_url)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.content, "xml") # Or html.parser if lxml not present
            for loc in soup.find_all("loc"):
                if loc.string and loc.string.startswith(base_url):
                    path = loc.string[len(base_url.rstrip('/')):]
                    if path.startswith("/"):
                        paths.add(path)
    except Exception as e:
        logger.debug(f"Crawl error {base_url}: {e}")
    return paths

async def _analyze_javascript(base_url: str) -> set[str]:
    """Extract and analyze linked JS bundles."""
    paths = set()
    try:
        resp = await _HTTP_CLIENT.get(base_url)
        if resp.status_code != 200:
            return paths
            
        soup = BeautifulSoup(resp.content, "html.parser")
        js_links = [script["src"] for script in soup.find_all("script", src=True)]
        
        # Limit to first 2 JS bundles to save time
        for js_link in js_links[:2]:
            if js_link.startswith("/"):
                js_url = f"{base_url.rstrip('/')}{js_link}"
            elif js_link.startswith("http"):
                if not js_link.startswith(base_url):
                    continue # Skip external JS
                js_url = js_link
            else:
                continue

            try:
                js_resp = await _HTTP_CLIENT.get(js_url)
                if js_resp.status_code == 200:
                    content = js_resp.text[:50000] # Read only first 50KB
                    # Look for hardcoded API routes, staging URLs, cloud buckets
                    for match in re.findall(r'[\'"](/(?:api|v[1-9]|admin|staging)[a-zA-Z0-9_\-\/]+)[\'"]', content):
                        paths.add(match)
                    for match in re.findall(r'https://[a-zA-Z0-9-]+\.s3\.amazonaws\.com', content):
                         paths.add(match) # Note: this is a full URL, we might need to handle it differently if returning paths
            except Exception as e:
                 logger.debug(f"JS analysis error {js_url}: {e}")
                 
    except Exception as e:
         logger.debug(f"JS extraction error {base_url}: {e}")
    return paths


async def _probe_sensitive_paths(base_url: str, is_catch_all: bool = False) -> list[dict]:
    """
    High-signal path probing for exposed sensitive files, with crawling, JS analysis,
    pattern matching, and response fingerprinting.
    """
    findings = []
    
    crawled_paths = await _crawl_links(base_url)
    js_paths = await _analyze_javascript(base_url)
    
    all_paths_to_probe = set([p["path"] for p in SENSITIVE_PATH_SIGNATURES])
    all_paths_to_probe.update(crawled_paths)
    all_paths_to_probe.update([p for p in js_paths if p.startswith("/")])
    
    # Optional: Apply random jitter/delay here or rely on _HTTP_CLIENT concurrency limits
    
    sem = asyncio.Semaphore(15) # Concurrency limit for path probing

    async def _probe(path: str):
        async with sem:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await _HTTP_CLIENT.get(url)
                
                # 1. Check Response Fingerprints (regardless of path or 200 status)
                for fp in FINGERPRINTS:
                    if fp["regex"].search(resp.text) or (fp["regex"].pattern == 'x-jenkins' and 'x-jenkins' in resp.headers):
                         return {
                             "path": path,
                             "type": fp["type"],
                             "severity": fp["severity"],
                             "url": url,
                             "matched_keyword": f"Fingerprint: {fp['app']}"
                         }

                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "").lower()
                    server_header = resp.headers.get("Server", "").lower()
                    body_text = resp.text
                    
                    # Guardrail 1: If a captcha/challenge page, drop it
                    if "captcha" in body_text.lower() and "challenge" in body_text.lower():
                        return None
                        
                    # Guardrail 2: Backup manifests (.bak, .zip, .old, .sql) are NEVER text/html files
                    is_backup_ext = any(path.endswith(ext) for ext in [".bak", ".old", ".zip", ".sql"])
                    if is_backup_ext and "text/html" in content_type:
                        return None

                    # Guardrail 3: Tech-stack mismatch for backend script files (e.g. .php, .asp, .jsp) on JS frameworks
                    is_backend_script = any(path.lower().endswith(ext) for ext in [".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi"])
                    if is_backend_script:
                        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                        powered_by = headers_lower.get("x-powered-by", "")
                        server_header_val = headers_lower.get("server", "")
                        
                        is_js_framework = (
                            "next.js" in powered_by or
                            "nextjs" in powered_by or
                            "nuxt" in powered_by or
                            "vercel" in server_header_val or
                            "netlify" in server_header_val or
                            "x-nextjs-cache" in headers_lower or
                            "x-vercel-cache" in headers_lower or
                            "x-nf-request-id" in headers_lower
                        )
                        if is_js_framework:
                            return None

                    # 2. Check predefined signatures if it's from the wordlist
                    signature = next((s for s in SENSITIVE_PATH_SIGNATURES if s["path"] == path), None)
                    if signature:
                         for k in signature["keywords"]:
                             if k.encode('utf-8') in resp.content:
                                 return {
                                     "path": path,
                                     "type": signature["type"],
                                     "severity": signature["severity"],
                                     "url": url,
                                     "matched_keyword": k
                                 }
                         
                         # Fallback: for .env files, check generic KEY=VALUE pattern
                         if path.startswith("/.env") and "text/html" not in content_type:
                             import re as _re
                             # Match lines like KEY=value (at least 3 such lines = likely a real .env)
                             env_lines = _re.findall(r'^[A-Z][A-Z0-9_]{2,}=.+', body_text, _re.MULTILINE)
                             if len(env_lines) >= 3:
                                 return {
                                     "path": path,
                                     "type": signature["type"],
                                     "severity": signature["severity"],
                                     "url": url,
                                     "matched_keyword": f"Generic .env ({len(env_lines)} vars detected)"
                                 }
                    
                    # 3. Check pattern matching for dynamically discovered paths
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern["regex"].search(path):
                            content_type = resp.headers.get("Content-Type", "")
                            
                            # If it's a catch-all server and response is HTML, it's almost certainly a false positive
                            if is_catch_all and "text/html" in content_type:
                                continue
                                
                            if pattern["type"] == "Suspicious Extension":
                                if "text/html" in content_type:
                                    continue # Skip soft 404s
                                    
                            # Check if the content is completely empty for files that shouldn't be
                            if pattern["type"] == "Suspicious Extension" and len(resp.content) == 0:
                                continue
                                
                            return {
                                "path": path,
                                "type": pattern["type"],
                                "severity": pattern["severity"],
                                "url": url,
                                "matched_keyword": f"Pattern: {pattern['regex'].pattern}"
                            }
                            
            except Exception:
                pass
            return None

    tasks = [_probe(p) for p in all_paths_to_probe]
    results = await asyncio.gather(*tasks)
    
    # Deduplicate by path
    found_paths = set()
    for r in results:
        if r and r["path"] not in found_paths:
            findings.append(r)
            found_paths.add(r["path"])
            
    # Add external bucket findings from JS analysis
    for bucket in [p for p in js_paths if p.startswith("http")]:
        findings.append({
            "path": bucket,
             "type": "Cloud Bucket Exposure",
             "severity": "medium",
             "url": bucket,
             "matched_keyword": "S3 Bucket"
        })
            
    return findings


async def _probe_http(hostname: str) -> dict:
    """
    Probe HTTP/HTTPS on a hostname.
    Returns: {status, tech_stack, sec_headers_grade, redirect_url, is_catch_all}
    """
    result = {
        "status": None,
        "tech_stack": [],
        "sec_headers_grade": "unknown",
        "is_catch_all": False,
        "final_url": None,
    }
    targets = [f"https://{hostname}", f"http://{hostname}"]
    for url in targets:
        try:
            resp = await _HTTP_CLIENT.get(url)
            body_preview = resp.text[:2000] if resp.text else ""
            result["status"] = resp.status_code
            result["tech_stack"] = _detect_tech_stack(str(resp.url), dict(resp.headers), resp.text)
            result["sec_headers_grade"] = _grade_security_headers(dict(resp.headers))
            result["final_url"] = str(resp.url)
            result["is_catch_all"] = await _test_catch_all(url)
            break
        except (httpx.TimeoutException, httpx.ConnectError, ssl.SSLError):
            continue
        except Exception as e:
            logger.debug(f"HTTP probe {url}: {e}")
            continue
    return result


async def _probe_tls(hostname: str) -> Optional[dict]:
    """
    Grab TLS certificate details for a hostname on port 443.
    Returns None if no TLS or connection fails.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=ctx, server_hostname=hostname),
            timeout=8.0,
        )
        cert_bin = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()

        if not cert_bin:
            return None

        cert = x509.load_der_x509_certificate(cert_bin)

        now = datetime.now(timezone.utc)
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        days_to_expiry = (valid_to - now).days
        is_expired = days_to_expiry < 0

        # Extract issuer
        issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not issuer_attrs:
            issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        issuer = issuer_attrs[0].value if issuer_attrs else "Unknown"

        # Subject
        subject_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        subject_name = subject_attrs[0].value if subject_attrs else hostname

        # SANs
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        is_self_signed = cert.issuer == cert.subject

        return {
            "issuer": issuer,
            "subject": subject_name,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "days_to_expiry": days_to_expiry,
            "sans": sans,
        }
    except Exception as e:
        logger.debug(f"TLS probe {hostname}: {e}")
        return None


async def _scan_port(host: str, port: int, timeout: float = 2.5) -> bool:
    """
    Try to open a TCP connection to host:port. Returns True if open.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _resolve_ip(hostname: str) -> Optional[str]:
    """DNS resolve hostname to IPv4 string."""
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        if info:
            return info[0][4][0]
    except Exception:
        pass
    return None


async def _resolve_geoip(ip: str) -> dict:
    """Fetch Provider (ISP/ASN) and Location (Country) for an IP address."""
    result = {"provider": None, "location": None}
    if not ip:
        return result
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=countryCode,isp")
            if resp.status_code == 200:
                data = resp.json()
                result["provider"] = data.get("isp")
                result["location"] = data.get("countryCode")
    except Exception as e:
        logger.debug(f"GeoIP probe {ip}: {e}")
    return result


import dns.asyncresolver

async def _check_email_security(domain: str) -> dict:
    """Check SPF and DMARC records via DNS."""
    result = {"spf": None, "dmarc": None, "dmarc_policy": "none", "spf_hardfail": False}
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # Check SPF
        try:
            answers = await resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = "".join([s.decode('utf-8') for s in rdata.strings])
                if txt.startswith("v=spf1"):
                    result["spf"] = txt
                    if "-all" in txt:
                        result["spf_hardfail"] = True
                    break
        except Exception:
            pass

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = await resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = "".join([s.decode('utf-8') for s in rdata.strings])
                if txt.startswith("v=DMARC1"):
                    result["dmarc"] = txt
                    match = re.search(r'p=(none|quarantine|reject)', txt, re.IGNORECASE)
                    if match:
                        result["dmarc_policy"] = match.group(1).lower()
                    break
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"Email security check failed for {domain}: {e}")
        
    return result


async def _generate_findings(
    tenant_id: uuid.UUID,
    hostname: str,
    http_result: dict,
    cert_info: Optional[dict],
    open_risky_ports: list[tuple[int, str, str]],  # [(port, service, risk)]
    sensitive_paths: list[dict],
    email_security: dict,
    is_exposed_admin: bool,
    cve_data: list[dict],
    nuclei_data: list[dict],
    asset_criticality: str,
    session: AsyncSession,
) -> None:
    """
    Auto-generate findings for security issues found during EASM scan.
    Deduplicates by entity+issue_type before inserting.
    Adjusts severity based on asset criticality and includes real CVEs.
    """
    # 1. Resolve base domain using ScanScope or fallback
    scopes_res = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.tenant_id == tenant_id,
                ScanScope.type == "domain"
            )
        )
    )
    domain_scopes = [s.value.lower().strip() for s in scopes_res.scalars().all()]

    def _get_base_domain(hn: str, scopes: list[str]) -> str:
        hn_lower = hn.lower().strip()
        matching_scopes = []
        for d in scopes:
            if hn_lower == d or hn_lower.endswith("." + d):
                matching_scopes.append(d)
        if matching_scopes:
            return max(matching_scopes, key=len)
        
        # Fallback if no matching scope found in DB
        parts = hn_lower.split('.')
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "edu", "gov", "ac"):
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return hn_lower

    base_domain = _get_base_domain(hostname, domain_scopes)

    findings_to_create = []

    def _adjust_severity(base_sev: str) -> str:
        levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        rev_levels = {v: k for k, v in levels.items()}
        val = levels.get(base_sev, 2)
        if asset_criticality in ("critical", "high"):
            val = min(4, val + 1)
        elif asset_criticality == "low":
            val = max(0, val - 1)
        return rev_levels.get(val, base_sev)

    # Potential CVE Findings (Layer 1 - Passive)
    for cve in cve_data:
        findings_to_create.append({
            "severity": "info",
            "source": "ext_scanner",
            "issue_type": f"Vulnerability {cve.get('cve_id')}",
            "entity": hostname,
            "tags": ["Potential", "CVE"],
            "evidence": {
                "hostname": hostname,
                "cve_id": cve.get("cve_id"),
                "cvss_score": cve.get("cvss_score"),
                "confidence": 20,
                "description": cve.get("description", "No description available.")
            },
        })

    # Verified Findings (Layer 2 - Active Nuclei Verification)
    for result in nuclei_data:
        findings_to_create.append({
            "severity": _adjust_severity(result.get("severity", "high")),
            "source": "ext_scanner",
            "issue_type": f"Verified {result.get('cve_id', 'Vulnerability')}",
            "entity": hostname,
            "tags": ["Verified", "Nuclei"],
            "evidence": {
                "hostname": hostname,
                "confidence": 95,
                "description": result.get("description"),
                "extracted_results": result.get("extracted_results")
            },
        })

    # Expired TLS certificate
    if cert_info and cert_info["is_expired"]:
        findings_to_create.append({
            "severity": _adjust_severity("medium"),
            "source": "ext_scanner",
            "issue_type": "Expired SSL Certificate",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info["issuer"],
                "expired_on": cert_info["valid_to"].isoformat(),
                "days_overdue": abs(cert_info["days_to_expiry"]),
            },
        })

    # Certificate expiring soon (< 30 days)
    if cert_info and not cert_info["is_expired"] and 0 < cert_info["days_to_expiry"] <= 30:
        findings_to_create.append({
            "severity": _adjust_severity("low"),
            "source": "ext_scanner",
            "issue_type": "SSL Certificate Expiring Soon",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info["issuer"],
                "expires_on": cert_info["valid_to"].isoformat(),
                "days_remaining": cert_info["days_to_expiry"],
            },
        })

    # Self-signed certificate
    if cert_info and cert_info["is_self_signed"]:
        findings_to_create.append({
            "severity": "medium",
            "source": "ext_scanner",
            "issue_type": "Self-Signed SSL Certificate",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info["issuer"],
            },
        })

    # Poor security headers
    if http_result["status"] and http_result["sec_headers_grade"] in ("D", "F"):
        grade = http_result["sec_headers_grade"]
        findings_to_create.append({
            "severity": _adjust_severity("medium" if grade == "D" else "high"),
            "source": "ext_scanner",
            "issue_type": "Poor Security Headers",
            "entity": base_domain,
            "evidence": {
                "hostname": hostname,
                "grade": grade,
                "affected_subdomains": [f"{hostname} (Grade {grade})"],
                "missing_headers": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options",
            },
        })

    # Risky open ports
    for port, service, risk in open_risky_ports:
        findings_to_create.append({
            "severity": _adjust_severity(risk),
            "source": "ext_scanner",
            "issue_type": f"Exposed {service} Port",
            "entity": f"{hostname}:{port}",
            "evidence": {
                "hostname": hostname,
                "port": port,
                "service": service,
                "internet_facing": True,
            },
        })

    # Sensitive paths
    for sp in sensitive_paths:
        findings_to_create.append({
            "severity": _adjust_severity(sp.get("severity", "critical")),
            "source": "ext_scanner",
            "issue_type": f"Exposed Sensitive File: {sp['type']}",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "url": sp["url"],
                "path": sp["path"],
                "matched_keyword": sp["matched_keyword"],
                "internet_facing": True,
            },
        })

    # Exposed admin panel
    if is_exposed_admin:
        findings_to_create.append({
            "severity": _adjust_severity("high"),
            "source": "ext_scanner",
            "issue_type": "Exposed Admin Panel",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "matched_keyword": any(kw in hostname for kw in ["admin", "portal", "manage", "cpanel", "wp-admin", "phpmyadmin"]),
                "internet_facing": True,
                "note": "Admin-named hostname is publicly reachable on the internet.",
            },
        })

    # Email Security (SPF / DMARC)
    if not email_security.get("dmarc"):
        findings_to_create.append({
            "severity": _adjust_severity("medium"),
            "source": "ext_scanner",
            "issue_type": "Missing DMARC Record",
            "entity": base_domain,
            "evidence": {
                "hostname": hostname,
                "affected_subdomains": [hostname],
                "description": "No DMARC record was found, making the domain vulnerable to email spoofing.",
            },
        })
    elif email_security.get("dmarc_policy") == "none":
        findings_to_create.append({
            "severity": _adjust_severity("low"),
            "source": "ext_scanner",
            "issue_type": "DMARC Policy is 'None'",
            "entity": base_domain,
            "evidence": {
                "hostname": hostname,
                "dmarc_record": email_security["dmarc"],
                "affected_subdomains": [hostname],
                "description": "DMARC is configured but the policy is set to 'none', meaning spoofed emails are not blocked.",
            },
        })
        
    if not email_security.get("spf"):
        findings_to_create.append({
            "severity": _adjust_severity("medium"),
            "source": "ext_scanner",
            "issue_type": "Missing SPF Record",
            "entity": base_domain,
            "evidence": {
                "hostname": hostname,
                "affected_subdomains": [hostname],
                "description": "No SPF record was found, allowing unauthorized senders to forge emails from this domain.",
            },
        })

    # Deduplicate findings_to_create by entity + issue_type
    unique_findings_map = {}
    for f in findings_to_create:
        key = (f["entity"], f["issue_type"])
        if key not in unique_findings_map:
            unique_findings_map[key] = f
        else:
            # Combine extracted results if possible
            existing_f = unique_findings_map[key]
            ex_results = existing_f["evidence"].get("extracted_results")
            new_results = f["evidence"].get("extracted_results")
            if new_results:
                if not ex_results:
                    existing_f["evidence"]["extracted_results"] = new_results
                else:
                    if not isinstance(ex_results, list):
                        ex_results = [ex_results]
                    if not isinstance(new_results, list):
                        new_results = [new_results]
                    
                    combined = list(set([str(x) for x in ex_results] + [str(x) for x in new_results]))
                    existing_f["evidence"]["extracted_results"] = combined

    # Upsert findings (check for existing by entity + issue_type)
    for f in unique_findings_map.values():
        existing = await session.execute(
            select(Finding).where(
                and_(
                    Finding.tenant_id == tenant_id,
                    Finding.entity == f["entity"],
                    Finding.issue_type == f["issue_type"],
                )
            )
        )
        existing_row = existing.scalars().first()
        if existing_row:
            # Update last_seen and re-open if resolved
            existing_row.last_seen_at = datetime.now(timezone.utc)
            if existing_row.status == "resolved":
                existing_row.status = "open"

            # Merge subdomains if it is one of the consolidated issues
            consolidated_issues = (
                "Poor Security Headers",
                "Missing DMARC Record",
                "DMARC Policy is 'None'",
                "Missing SPF Record"
            )
            if f["issue_type"] in consolidated_issues:
                from sqlalchemy.orm.attributes import flag_modified
                current_evidence = dict(existing_row.evidence or {})
                affected = list(current_evidence.get("affected_subdomains") or [])
                new_subs = f["evidence"].get("affected_subdomains") or []
                
                # Merge subdomains while avoiding exact duplicates
                for ns in new_subs:
                    if ns not in affected:
                        affected.append(ns)
                
                current_evidence["affected_subdomains"] = affected
                
                if f["issue_type"] == "Poor Security Headers":
                    # Keep grade F if either is F, otherwise D
                    current_evidence["grade"] = "F" if (current_evidence.get("grade") == "F" or f["evidence"].get("grade") == "F") else "D"
                
                existing_row.evidence = current_evidence
                flag_modified(existing_row, "evidence")
                
                # Promote severity to the highest observed severity
                sev_hierarchy = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                existing_sev = existing_row.severity
                new_sev = f["severity"]
                if sev_hierarchy.get(new_sev, 0) > sev_hierarchy.get(existing_sev, 0):
                    existing_row.severity = new_sev
        else:
            # Get next sequence number (manual since we don't use server-side default)
            from sqlalchemy import func as sqlfunc, text
            seq_result = await session.execute(text("SELECT nextval('findings_seq')"))
            seq_num = seq_result.scalar()
            session.add(Finding(
                tenant_id=tenant_id,
                finding_num=seq_num,
                severity=f["severity"],
                source=f["source"],
                issue_type=f["issue_type"],
                entity=f["entity"],
                tags=f.get("tags", []),
                evidence=f["evidence"],
                status="open",
            ))


async def scan_domain(
    tenant_id: uuid.UUID,
    hostname: str,
    modules: list[str] | None = None
) -> None:
    """
    Full EASM scan for a single hostname.
    Runs all probes concurrently and stores results.
    Gated by _GLOBAL_SCAN_SEM to prevent resource exhaustion.
    """
    async with _GLOBAL_SCAN_SEM:
        await _scan_domain_inner(tenant_id, hostname, modules)


async def _scan_domain_inner(
    tenant_id: uuid.UUID,
    hostname: str,
    modules: list[str] | None = None
) -> None:
    """Inner implementation of scan_domain, runs under the global semaphore."""
    logger.info(f"[EASM] Scanning {hostname} for tenant {tenant_id}")

    # Run probes concurrently
    async def dummy_http(): return {}
    async def dummy_tls(): return None
    
    do_web = not modules or "web" in modules
    do_ports = not modules or "ports" in modules

    http_task = asyncio.create_task(_probe_http(hostname) if do_web else dummy_http())
    tls_task = asyncio.create_task(_probe_tls(hostname) if do_web else dummy_tls())
    ip_task = asyncio.create_task(_resolve_ip(hostname))

    # Port scan (concurrent within a semaphore)
    sem = asyncio.Semaphore(10)

    async def _guarded_port(host, port, timeout=1.5):
        async with sem:
            return await _scan_port(host, port, timeout)

    active_ports = COMMON_PORTS if do_ports else []
    if do_ports and hostname in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        active_ports = [p for p in COMMON_PORTS if p[0] not in (3000, 8000)]

    port_tasks = {
        (port, svc, risk): asyncio.create_task(_guarded_port(hostname, port))
        for port, svc, risk in active_ports
    }

    # Await all
    http_result = await http_task
    cert_info = await tls_task
    ip_address = await ip_task
    port_results = {k: await v for k, v in port_tasks.items()}

    geoip_info = await _resolve_geoip(ip_address)
    is_catch_all = http_result.get("is_catch_all", False)

    # Gather all open web endpoints
    open_web_urls = set()
    if http_result.get("final_url"):
        open_web_urls.add(http_result["final_url"])
        
    for (port, svc, risk), is_open in port_results.items():
        if is_open and svc in ("HTTP", "HTTP-Alt", "HTTPS", "HTTPS-Alt"):
            scheme = "https" if "HTTPS" in svc else "http"
            open_web_urls.add(f"{scheme}://{hostname}:{port}")

    # Sensitive path probe
    sensitive_findings = []
    if do_web:
        for web_url in open_web_urls:
            is_catch = await _test_catch_all(web_url)
            findings = await _probe_sensitive_paths(web_url, is_catch_all=is_catch)
            sensitive_findings.extend(findings)
        
    # Email security probe
    do_email = not modules or "email" in modules
    email_security = await _check_email_security(hostname) if do_email else {}

    is_admin = any(kw in hostname for kw in ["admin", "portal", "manage", "cpanel", "wp-admin", "phpmyadmin"])
    http_status = http_result.get("status")
    tech_stack = http_result.get("tech_stack", [])
    grade = http_result.get("sec_headers_grade", "unknown")
    
    # Calculate context-aware criticality
    criticality = "unknown"
    if any(w in hostname for w in ["prod", "api", "app", "www", "main"]):
        criticality = "high"
    elif any(w in hostname for w in ["dev", "test", "staging", "qa"]):
        criticality = "low"
    elif is_admin:
        criticality = "critical"
    else:
        criticality = "medium"

    # Run Passive CVE Mapping only (Nuclei runs as a separate phase after all hosts are scanned)
    do_vuln = not modules or "vuln" in modules
    
    async def dummy_cve(): return []
    cve_data = await (_calculate_cve_data(tech_stack) if do_vuln else dummy_cve())
    
    # Nuclei data is empty here — it will be populated in the separate Nuclei phase
    nuclei_data = []
    cve_count = len(cve_data)

    from app.database import get_tenant_db
    async with get_tenant_db(str(tenant_id)) as session:
        # ── Upsert easm_assets ──────────────────────────────────────────────────────────
        existing_asset = await session.execute(
            select(EasmAsset).where(
                and_(
                    EasmAsset.tenant_id == tenant_id,
                    EasmAsset.hostname == hostname,
                )
            )
        )
        asset = existing_asset.scalar_one_or_none()

        if asset:
            asset.ip_address = ip_address
            asset.http_status = http_status
            asset.tech_stack = [json.dumps(t) for t in tech_stack]
            asset.sec_headers_grade = grade
            asset.cve_count = cve_count
            asset.is_catch_all = is_catch_all
            asset.is_exposed_admin = is_admin
            asset.asset_criticality = criticality
            asset.last_seen_at = datetime.now(timezone.utc)
            asset.updated_at = datetime.now(timezone.utc)
        else:
            asset = EasmAsset(
                tenant_id=tenant_id,
                hostname=hostname,
                ip_address=ip_address,
                http_status=http_status,
                asset_type="admin" if is_admin else "web",
                tech_stack=[json.dumps(t) for t in tech_stack],
                sec_headers_grade=grade,
                cve_count=cve_count,
                is_catch_all=is_catch_all,
                is_exposed_admin=is_admin,
                asset_criticality=criticality,
                status="active",
            )
            session.add(asset)
        await session.flush()

        # \u2500\u2500 Upsert easm_certificates \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if cert_info:
            existing_cert = await session.execute(
                select(EasmCertificate).where(
                    and_(
                        EasmCertificate.tenant_id == tenant_id,
                        EasmCertificate.hostname == hostname,
                    )
                )
            )
            cert_row = existing_cert.scalar_one_or_none()
            if cert_row:
                cert_row.issuer = cert_info["issuer"]
                cert_row.valid_from = cert_info["valid_from"]
                cert_row.valid_to = cert_info["valid_to"]
                cert_row.is_expired = cert_info["is_expired"]
                cert_row.is_self_signed = cert_info["is_self_signed"]
                cert_row.days_to_expiry = cert_info["days_to_expiry"]
                cert_row.sans = cert_info["sans"]
                cert_row.updated_at = datetime.now(timezone.utc)
            else:
                session.add(EasmCertificate(
                    tenant_id=tenant_id,
                    hostname=hostname,
                    issuer=cert_info["issuer"],
                    subject=cert_info["subject"],
                    fingerprint=None,
                    valid_from=cert_info["valid_from"],
                    valid_to=cert_info["valid_to"],
                    is_expired=cert_info["is_expired"],
                    is_self_signed=cert_info["is_self_signed"],
                    days_to_expiry=cert_info["days_to_expiry"],
                    sans=cert_info["sans"],
                ))

        # \u2500\u2500 Upsert easm_ports \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        risky_open: list[tuple[int, str, str]] = []
        for (port, svc, risk), is_open in port_results.items():
            if not is_open:
                continue
            is_risky = port in RISKY_PORTS
            if is_risky:
                risky_open.append((port, svc, risk))

            existing_port = await session.execute(
                select(EasmPort).where(
                    and_(
                        EasmPort.tenant_id == tenant_id,
                        EasmPort.ip_address == ip_address,
                        EasmPort.port == port,
                    )
                )
            )
            port_row = existing_port.scalar_one_or_none()
            if port_row:
                port_row.last_seen_at = datetime.now(timezone.utc)
                port_row.is_risky = is_risky
                # Update geoip in case it changed
                if geoip_info["provider"]:
                    port_row.provider = geoip_info["provider"]
                if geoip_info["location"]:
                    port_row.location = geoip_info["location"]
            else:
                session.add(EasmPort(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    ip_address=ip_address or "0.0.0.0",
                    port=port,
                    protocol="tcp",
                    service=svc,
                    banner=None,
                    provider=geoip_info.get("provider"),
                    location=geoip_info.get("location"),
                    risk_level=risk,
                    is_risky=is_risky,
                ))

        # ── Auto-generate findings ───────────────────────────────────────────
        try:
            await _generate_findings(
                tenant_id, hostname, http_result, cert_info, risky_open,
                sensitive_findings, email_security, is_admin, cve_data, nuclei_data, criticality, session
            )
        except Exception as e:
            logger.warning(f"[EASM] Finding generation error for {hostname}: {e}")

        await session.flush()
        logger.info(f"[EASM] Done {hostname}: status={http_status} grade={grade} ports={len(risky_open)} risky admin={is_admin}")



async def _is_job_cancelled(tenant_id: str, job_id: uuid.UUID | None) -> bool:
    if not job_id:
        return False
    try:
        from app.database import get_tenant_db
        from sqlalchemy import select as _select
        async with get_tenant_db(tenant_id) as session:
            result = await session.execute(_select(ScanJob.status).where(ScanJob.id == job_id))
            row = result.first()
            if row and row[0] in ("failed", "completed"):
                return True
    except Exception as e:
        logger.warning(f"[EASM] Error checking scan job cancel status: {e}")
    return False


async def run_easm_scan(tenant_id: str, scope_values: list[str], modules: list[str] | None = None) -> None:
    """
    Main entry point: scan all domains in the tenant's scope.
    Called as a background task after onboarding or manual rescan.
    Creates a ScanJob record and updates its status throughout.

    Step 0: Subdomain enumeration via passive sources (crt.sh, HackerTarget).
    Step 1: Full EASM scan for each discovered host.
    """
    tid = uuid.UUID(tenant_id)
    
    # ── Create queued job immediately ─────────────────────────────────────────
    job_id: uuid.UUID | None = None
    try:
        async with get_tenant_db(tenant_id) as session:
            job = ScanJob(
                tenant_id=tid,
                job_type="easm",
                status="queued",
                started_at=datetime.now(timezone.utc),
                metadata_={
                    "targets": scope_values,
                    "modules": modules,
                    "all_hosts": [],
                    "total": 0,
                    "completed": 0,
                    "failed": 0,
                    "subdomains_found": 0,
                },
            )
            session.add(job)
            await session.commit()
            job_id = job.id
    except Exception as e:
        logger.error(f"[EASM] Could not create queued ScanJob: {e}")

    # ── Per-tenant queue: run concurrent scans sequentially ───────────────────
    lock = _get_tenant_lock(tenant_id)
    if lock.locked():
        logger.info(f"[EASM] Scan already running for tenant {tenant_id}, queuing this scan...")
        
    async with lock:
        await _run_easm_scan_inner(tenant_id, scope_values, passed_job_id=job_id, modules=modules)


async def _run_easm_scan_inner(tenant_id: str, scope_values: list[str], passed_job_id: uuid.UUID | None = None, modules: list[str] | None = None) -> None:
    """Inner implementation of run_easm_scan, runs under the per-tenant guard."""
    tid = uuid.UUID(tenant_id)
    root_domains = [s for s in scope_values if not _is_cidr(s)]
    cidrs = [s for s in scope_values if _is_cidr(s)]
    logger.info(f"[EASM] Starting scan for tenant {tenant_id}, {len(root_domains)} domain(s), {len(cidrs)} CIDR(s)")

    # ── Expand CIDRs ──────────────────────────────────────────────────────────
    ip_targets: list[str] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.num_addresses == 1:
                ip_targets.append(str(net.network_address))
            else:
                for ip in net.hosts():
                    ip_targets.append(str(ip))
        except ValueError:
            pass

    # ── Step 0: Passive subdomain enumeration ─────────────────────────────────
    all_domains: list[str] = []
    subdomain_map: dict[str, list[str]] = {}  # root → [subs]

    for root in root_domains:
        if not modules or "subdomains" in modules:
            subs = await _enumerate_subdomains(root)
        else:
            subs = []
        # Always include the root itself
        hosts = list({root} | set(subs))
        subdomain_map[root] = hosts
        all_domains.extend(hosts)
        logger.info(f"[EASM] {root}: {len(subs)} subdomains discovered → {len(hosts)} total hosts")

    # Deduplicate across roots while preserving order
    seen: set[str] = set()
    domains: list[str] = []
    for d in all_domains:
        if d not in seen:
            seen.add(d)
            domains.append(d)

    # Add expanded IP targets
    for ip in ip_targets:
        if ip not in seen:
            seen.add(ip)
            domains.append(ip)

    total_subdomains = len(all_domains) - len(root_domains)

    # ── Create/Update scan job record ─────────────────────────────────────────
    job_id: uuid.UUID | None = passed_job_id
    try:
        async with get_tenant_db(tenant_id) as session:
            if job_id:
                from sqlalchemy import select as _select
                result = await session.execute(_select(ScanJob).where(ScanJob.id == job_id))
                job = result.scalar_one_or_none()
                if job:
                    job.status = "running"
                    job.metadata_ = {
                        "targets": scope_values,
                        "all_hosts": domains,
                        "total": len(domains),
                        "completed": 0,
                        "failed": 0,
                        "subdomains_found": total_subdomains,
                    }
                    await session.commit()
            else:
                job = ScanJob(
                    tenant_id=tid,
                    job_type="easm",
                    status="running",
                    started_at=datetime.now(timezone.utc),
                    metadata_={
                        "targets": scope_values,
                        "all_hosts": domains,
                        "total": len(domains),
                        "completed": 0,
                        "failed": 0,
                        "subdomains_found": total_subdomains,
                    },
                )
                session.add(job)
                await session.flush()
                job_id = job.id
                logger.info(f"[EASM] Created scan job {job_id} ── {len(domains)} hosts to scan")
    except Exception as e:
        logger.warning(f"[EASM] Could not update/create scan job record: {e}")

    # ── Scan each host (batched to prevent resource exhaustion) ─────────────
    import gc
    completed = 0
    failed = 0
    BATCH_SIZE = 1  # Process 1 host at a time to stay under 512MB RAM
    
    async def _worker(domain_to_scan: str):
        try:
            await scan_domain(tid, domain_to_scan, modules)
            return (domain_to_scan, True)
        except Exception as e:
            logger.error(f"[EASM] Failed to scan {domain_to_scan}: {e}")
            return (domain_to_scan, False)

    for i in range(0, len(domains), BATCH_SIZE):
        # Check if cancelled before starting batch
        if await _is_job_cancelled(tenant_id, job_id):
            logger.info(f"[EASM] Scan job {job_id} cancelled by user. Exiting discovery loop.")
            return

        batch = domains[i:i + BATCH_SIZE]
        logger.info(f"[EASM] Scanning batch {i // BATCH_SIZE + 1}/{(len(domains) + BATCH_SIZE - 1) // BATCH_SIZE}: {len(batch)} host(s)")
        
        tasks = [asyncio.create_task(_worker(d)) for d in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                failed += 1
            elif isinstance(result, tuple) and result[1]:
                completed += 1
            else:
                failed += 1

        # Update progress on job record after each batch
        if job_id:
            try:
                async with get_tenant_db(tenant_id) as session:
                    from sqlalchemy import select as _select
                    result = await session.execute(_select(ScanJob).where(ScanJob.id == job_id))
                    j = result.scalar_one_or_none()
                    if j:
                        # Don't overwrite if it was cancelled mid-transaction
                        if j.status in ("failed", "completed"):
                            logger.info(f"[EASM] Scan job {job_id} cancelled or finished. Exiting progress update.")
                            return
                        j.metadata_ = {
                            "targets": scope_values,
                            "all_hosts": domains,
                            "total": len(domains),
                            "completed": completed,
                            "failed": failed,
                            "subdomains_found": total_subdomains,
                        }
                        await session.commit()
            except Exception:
                pass
        
        # Force GC between batches to reclaim memory
        gc.collect()

    # ── Mark asset discovery phase complete ────────────────────────────────
    logger.info(f"[EASM] Asset discovery complete for tenant {tenant_id}: {completed} ok, {failed} failed, {total_subdomains} subdomains found")

    # ── Phase 2: Run Nuclei vulnerability scanning separately ─────────────
    # Check if cancelled before starting Nuclei
    if await _is_job_cancelled(tenant_id, job_id):
        logger.info(f"[EASM] Scan job {job_id} cancelled by user. Skipping Nuclei phase.")
        return

    nuclei_ok = 0
    nuclei_fail = 0
    try:
        nuclei_ok, nuclei_fail = await _run_nuclei_phase(tenant_id, domains, modules, job_id=job_id)
    except Exception as e:
        logger.error(f"[EASM] Nuclei phase failed: {e}")

    # ── Mark job complete ────────────────────────────────────────────────────
    if job_id:
        try:
            async with get_tenant_db(tenant_id) as session:
                from sqlalchemy import select as _select
                result = await session.execute(_select(ScanJob).where(ScanJob.id == job_id))
                j = result.scalar_one_or_none()
                if j:
                    if j.status in ("failed", "completed"):
                        logger.info(f"[EASM] Scan job {job_id} was cancelled or finished. Not overwriting status.")
                        return
                    j.status = "completed" if failed == 0 else "failed"
                    j.completed_at = datetime.now(timezone.utc)
                    j.metadata_ = {
                        "targets": scope_values,
                        "all_hosts": domains,
                        "total": len(domains),
                        "completed": completed,
                        "failed": failed,
                        "subdomains_found": total_subdomains,
                        "nuclei_scanned": nuclei_ok,
                        "nuclei_failed": nuclei_fail,
                    }
                    if failed > 0:
                        j.error_message = f"{failed} host(s) failed to scan"
                    await session.commit()
        except Exception as e:
            logger.warning(f"[EASM] Could not update scan job: {e}")

    logger.info(f"[EASM] Scan fully complete for tenant {tenant_id}: {completed} ok, {failed} failed, nuclei={nuclei_ok}/{nuclei_ok+nuclei_fail}")


# ── Nuclei Vulnerability Scan Phase (runs separately after asset discovery) ────

async def _run_nuclei_phase(tenant_id: str, domains: list[str], modules: list[str] | None = None, job_id: uuid.UUID | None = None) -> tuple[int, int]:
    """
    Phase 2 of the EASM scan: Run Nuclei vulnerability scanning.
    
    This runs AFTER all assets have been discovered and stored in the DB.
    Scans in batches of 10 hostnames to balance speed and low memory usage under 512MB.
    Returns (ok_count, fail_count).
    """
    import gc
    from urllib.parse import urlparse
    
    do_vuln = not modules or "vuln" in modules
    if not do_vuln:
        return (0, 0)
    
    engine = NucleiVerificationEngine()
    if not engine.nuclei_bin.exists():
        logger.warning("[EASM/Nuclei] Nuclei binary not found, skipping vulnerability scan phase")
        return (0, 0)
    
    tid = uuid.UUID(tenant_id)
    ok_count = 0
    fail_count = 0
    
    logger.info(f"[EASM/Nuclei] Starting vulnerability scan phase for {len(domains)} host(s)")
    
    # 1. Helper to extract hostname from matched-at URL
    def _extract_hostname(matched_at: str, fallback: str) -> str:
        if not matched_at:
            return fallback
        try:
            parsed = urlparse(matched_at)
            host = parsed.hostname
            if host:
                return host.lower().strip()
        except Exception:
            pass
        return fallback

    # 2. Batch targets in groups of 15
    NUCLEI_BATCH_SIZE = 15
    batches = [domains[i:i + NUCLEI_BATCH_SIZE] for i in range(0, len(domains), NUCLEI_BATCH_SIZE)]
    
    for batch_idx, batch_domains in enumerate(batches):
        # Check if cancelled before starting batch
        if await _is_job_cancelled(tenant_id, job_id):
            logger.info(f"[EASM/Nuclei] Scan job {job_id} cancelled by user. Exiting Nuclei phase batch {batch_idx + 1}.")
            break

        # Update progress metadata in database
        if job_id:
            try:
                async with get_tenant_db(tenant_id) as session:
                    from sqlalchemy import select as _select
                    result = await session.execute(_select(ScanJob).where(ScanJob.id == job_id))
                    j = result.scalar_one_or_none()
                    if j:
                        # Check cancellation once more in transaction context
                        if j.status in ("failed", "completed"):
                            logger.info(f"[EASM/Nuclei] Scan job {job_id} cancelled or finished. Exiting progress update.")
                            break
                        meta = dict(j.metadata_ or {})
                        meta["phase"] = "vuln"
                        meta["vuln_total"] = len(domains)
                        meta["vuln_completed"] = ok_count
                        meta["vuln_failed"] = fail_count
                        j.metadata_ = meta
                        await session.commit()
            except Exception as e:
                logger.warning(f"[EASM/Nuclei] Could not update scan job progress metadata: {e}")

        batch_targets = set()
        batch_tech_tags = set()
        asset_info_map = {}  # hostname -> {"criticality": str}
        
        # Load asset details and port details for all domains in batch
        try:
            async with get_tenant_db(tenant_id) as session:
                for hostname in batch_domains:
                    result = await session.execute(
                        select(EasmAsset).where(
                            and_(
                                EasmAsset.tenant_id == tid,
                                EasmAsset.hostname == hostname,
                            )
                        )
                    )
                    asset = result.scalar_one_or_none()
                    if not asset:
                        continue
                    
                    asset_info_map[hostname] = {
                        "criticality": asset.asset_criticality or "medium",
                        "findings_found": 0
                    }
                    
                    # Tech tags
                    for t in (asset.tech_stack or []):
                        try:
                            obj = json.loads(t) if isinstance(t, str) else t
                            if obj.get("name"):
                                batch_tech_tags.add(obj["name"].lower().replace(" ", "-"))
                        except (json.JSONDecodeError, TypeError):
                            pass
                    
                    # Ports/Web URLs
                    port_result = await session.execute(
                        select(EasmPort).where(
                            and_(
                                EasmPort.tenant_id == tid,
                                EasmPort.asset_id == asset.id,
                            )
                        )
                    )
                    ports = port_result.scalars().all()
                    
                    for p in ports:
                        if p.service in ("HTTP", "HTTP-Alt", "HTTPS", "HTTPS-Alt"):
                            scheme = "https" if "HTTPS" in p.service else "http"
                            batch_targets.add(f"{scheme}://{hostname}:{p.port}")
                    
                    if asset.http_status:
                        batch_targets.add(f"https://{hostname}")
                        batch_targets.add(f"http://{hostname}")
        except Exception as e:
            logger.error(f"[EASM/Nuclei] Error loading batch assets: {e}")
            fail_count += len(batch_domains)
            continue
            
        if not batch_targets:
            logger.info(f"[EASM/Nuclei] Batch {batch_idx + 1} has no open web targets. Skipping.")
            ok_count += len(batch_domains)
            continue
            
        # Run Nuclei scan for the batch
        try:
            targets_list = list(batch_targets)
            tags_list = list(batch_tech_tags)
            logger.info(f"[EASM/Nuclei] Batch {batch_idx + 1}/{len(batches)}: Scanning {len(batch_domains)} host(s) via {len(targets_list)} URLs. Tech tags: {tags_list}")
            
            raw_nuclei_data = await engine.verify(targets_list, tags=tags_list)
            
            # Filter detections
            nuclei_findings = []
            for n in raw_nuclei_data:
                t_id = str(n.get("template_id", "")).lower()
                if "wappalyzer" in t_id or t_id.endswith("-detect") or "tech" in t_id:
                    continue
                nuclei_findings.append(n)
                
            # Write findings to DB in batch session
            if nuclei_findings:
                async with get_tenant_db(tenant_id) as session:
                    # Map each finding back to its correct hostname
                    for result_item in nuclei_findings:
                        matched_at = result_item.get("matched_at", "")
                        # Try to resolve to a host in the current batch
                        finding_host = _extract_hostname(matched_at, batch_domains[0])
                        
                        # Find the correct criticality or fallback
                        host_info = asset_info_map.get(finding_host, {"criticality": "medium"})
                        asset_criticality = host_info.get("criticality", "medium")
                        
                        def _adjust_severity(base_sev: str) -> str:
                            levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                            rev_levels = {v: k for k, v in levels.items()}
                            val = levels.get(base_sev, 2)
                            if asset_criticality in ("critical", "high"):
                                val = min(4, val + 1)
                            elif asset_criticality == "low":
                                val = max(0, val - 1)
                            return rev_levels.get(val, base_sev)
                            
                        issue_type = f"Verified {result_item.get('cve_id', 'Vulnerability')}"
                        
                        # Deduplicate
                        existing = await session.execute(
                            select(Finding).where(
                                and_(
                                    Finding.tenant_id == tid,
                                    Finding.entity == finding_host,
                                    Finding.issue_type == issue_type,
                                )
                            )
                        )
                        if existing.scalar_one_or_none():
                            continue
                            
                        from sqlalchemy import text as _text
                        seq_result = await session.execute(_text("SELECT nextval('findings_seq')"))
                        seq_num = seq_result.scalar()
                        
                        session.add(Finding(
                            tenant_id=tid,
                            finding_num=seq_num,
                            severity=_adjust_severity(result_item.get("severity", "high")),
                            source="ext_scanner",
                            issue_type=issue_type,
                            entity=finding_host,
                            tags=["Verified", "Nuclei"],
                            evidence={
                                "hostname": finding_host,
                                "confidence": 95,
                                "description": result_item.get("description"),
                                "extracted_results": result_item.get("extracted_results"),
                                "matched_at": result_item.get("matched_at"),
                                "template_id": result_item.get("template_id"),
                            },
                        ))
                        
                        # Increment finding count for host update
                        if finding_host in asset_info_map:
                            asset_info_map[finding_host]["findings_found"] = asset_info_map[finding_host].get("findings_found", 0) + 1

                    # Bulk update asset CVE count
                    for hname, info in asset_info_map.items():
                        findings_count = info.get("findings_found", 0)
                        if findings_count > 0:
                            result = await session.execute(
                                select(EasmAsset).where(
                                    and_(
                                        EasmAsset.tenant_id == tid,
                                        EasmAsset.hostname == hname,
                                    )
                                )
                            )
                            asset_row = result.scalar_one_or_none()
                            if asset_row:
                                asset_row.cve_count = (asset_row.cve_count or 0) + findings_count
                                asset_row.updated_at = datetime.now(timezone.utc)
                                
                    await session.commit()
                    
            ok_count += len(batch_domains)
            logger.info(f"[EASM/Nuclei] Batch {batch_idx + 1} done. Found {len(nuclei_findings)} verified vulnerabilities across {len(batch_domains)} hosts.")
        except Exception as e:
            logger.error(f"[EASM/Nuclei] Batch {batch_idx + 1} scan failed: {e}")
            fail_count += len(batch_domains)
            
        # Reclaim memory after each batch
        gc.collect()
        
    logger.info(f"[EASM/Nuclei] Phase complete: {ok_count} ok, {fail_count} failed")
    return (ok_count, fail_count)


# ── Passive subdomain enumeration ─────────────────────────────────────────────

async def _enumerate_subdomains(root_domain: str) -> list[str]:
    """
    Passively aggregate subdomains from multiple public sources:
      1. crt.sh — Certificate Transparency log search
      2. HackerTarget — Passive DNS / IP lookup
    Returns a deduplicated list of subdomains (not including the root itself).
    """
    subdomains: set[str] = set()

    results = await asyncio.gather(
        _crtsh_subdomains(root_domain),
        _hackertarget_subdomains(root_domain),
        return_exceptions=True,
    )

    for result in results:
        if isinstance(result, Exception):
            logger.debug(f"[EASM] Subdomain source error for {root_domain}: {result}")
            continue
        subdomains.update(result)

    # Filter: must end with .root_domain and not contain wildcards
    clean = set()
    for sub in subdomains:
        sub = sub.strip().lower().lstrip("*.")
        if sub and (sub.endswith(f".{root_domain}") or sub == root_domain):
            if "*" not in sub:
                clean.add(sub)

    # Remove the root itself — caller adds it
    clean.discard(root_domain)
    logger.info(f"[EASM] crt.sh+HackerTarget found {len(clean)} unique subdomains for {root_domain}")
    return sorted(clean)


async def _crtsh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains.
    Returns list of unique names from matching certificates.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url)
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                # crt.sh can return multi-line name_value
                for line in name.split("\n"):
                    line = line.strip().lower().lstrip("*.")
                    if line:
                        subdomains.add(line)
    except Exception as e:
        logger.debug(f"[EASM] crt.sh error for {domain}: {e}")
    return list(subdomains)


async def _hackertarget_subdomains(domain: str) -> list[str]:
    """
    Query HackerTarget passive DNS for subdomains.
    Returns list of unique hostnames.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.split(",")
                if parts:
                    host = parts[0].strip().lower()
                    if host and "error" not in host and "api count" not in host:
                        subdomains.add(host)
    except Exception as e:
        logger.debug(f"[EASM] HackerTarget error for {domain}: {e}")
    return list(subdomains)


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
