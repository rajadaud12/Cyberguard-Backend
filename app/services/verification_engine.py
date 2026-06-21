import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

import shutil

# Global lock to serialize Nuclei scans to prevent RAM exhaustion (OOM) on low-resource servers
_NUCLEI_SEM = asyncio.Semaphore(1)

# Hard cap on total templates per phase to keep scan time bounded
MAX_TEMPLATES_PER_PHASE = 80

# Nuclei subprocess timeout per batch (seconds) — must be well under Render's 100s request limit
NUCLEI_BATCH_TIMEOUT = 90

class NucleiVerificationEngine:
    def __init__(self):
        # Resolve backend root directory (two levels up from app/services/verification_engine.py)
        self.base_dir = Path(__file__).parent.parent.parent.absolute()
        self.templates_dir = self.base_dir / "bin" / "nuclei-templates"

        # 1. First, check if nuclei is installed globally in the system PATH
        system_nuclei = shutil.which("nuclei")
        if system_nuclei:
            self.nuclei_bin = Path(system_nuclei)
            logger.info(f"Using system-wide Nuclei binary at {self.nuclei_bin}")
        else:
            # 2. Fall back to local bin/ folder (nuclei.exe on Windows, nuclei on Linux)
            is_windows = os.name == "nt"
            bin_name = "nuclei.exe" if is_windows else "nuclei"
            self.nuclei_bin = self.base_dir / "bin" / bin_name
            if not self.nuclei_bin.exists():
                logger.warning(f"Nuclei binary not found in bin/ or system PATH at {self.nuclei_bin}")

    def _find_matching_templates(self, folders: list[str], tags: str, max_results: int = MAX_TEMPLATES_PER_PHASE) -> list[str]:
        matching_paths = []
        if not self.templates_dir.exists() or not tags:
            return []
            
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
        if not tag_list:
            return []
            
        tag_set = set(tag_list)
        
        import re
        tags_re = re.compile(r'^\s*tags:\s*(.+)$', re.MULTILINE)
        max_req_re = re.compile(r'max-request:\s*(\d+)', re.IGNORECASE)
        
        for folder in folders:
            if len(matching_paths) >= max_results:
                break
            folder_path = self.templates_dir / folder
            if not folder_path.exists():
                continue
                
            for root, _, files in os.walk(folder_path):
                if len(matching_paths) >= max_results:
                    break
                for file in files:
                    if len(matching_paths) >= max_results:
                        break
                    if file.endswith(".yaml") or file.endswith(".yml"):
                        file_path = os.path.join(root, file)
                        try:
                            # Read first 1500 chars (fast pre-filter)
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                head = f.read(1500).lower()
                                
                                # Skip heavy brute force/directory fuzzing templates
                                max_req_match = max_req_re.search(head)
                                if max_req_match:
                                    if int(max_req_match.group(1)) > 30:
                                        continue
                                        
                                match = tags_re.search(head)
                                if match:
                                    raw_tags = match.group(1).strip().strip('"\'[]{}')
                                    template_tags = {t.strip().lower() for t in raw_tags.split(",") if t.strip()}
                                    if tag_set.intersection(template_tags):
                                        matching_paths.append(file_path)
                                else:
                                    # Fallback to simple substring match
                                    if "tags:" in head and any(t in head for t in tag_set):
                                        matching_paths.append(file_path)
                        except Exception:
                            pass

        logger.info(f"[Nuclei] Pre-filtered templates for folders {folders} and tags {tags}: found {len(matching_paths)} matches (capped at {max_results})")
        return matching_paths

    async def _filter_active_targets(self, targets: list[str]) -> list[str]:
        """Verify that target URLs are responsive before passing them to Nuclei to prevent hangs."""
        import httpx
        
        async def check_target(url: str):
            try:
                async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=2.0)) as client:
                    await client.get(url, follow_redirects=False)
                    return url
            except Exception as e:
                logger.warning(f"[Nuclei/PreCheck] Target {url} is unresponsive (skipped): {e}")
                return None

        results = await asyncio.gather(*[check_target(t) for t in targets])
        active_targets = [r for r in results if r]
        
        logger.info(f"[Nuclei/PreCheck] Filtered targets: {len(targets)} input -> {len(active_targets)} active")
        return active_targets

    async def verify(self, target_url: str | list[str], tags: list[str]) -> list[dict]:
        if not self.nuclei_bin.exists():
            logger.error("Nuclei binary not found. Skipping verification.")
            return []

        async with _NUCLEI_SEM:
            results = []

            # Normalize targets
            targets = target_url if isinstance(target_url, list) else [target_url]
            if not targets:
                return []

            # Filter out unresponsive targets
            targets = await self._filter_active_targets(targets)
            if not targets:
                logger.info("[Nuclei/PreCheck] No responsive targets found. Skipping verification.")
                return []

            # Build deduplicated base targets (root URLs only) for phases 1 & 2
            from urllib.parse import urlparse
            base_targets = list({
                f"{urlparse(t).scheme}://{urlparse(t).netloc}/"
                for t in targets
            })

            # ── Phase 1: Broad exposure/misconfig scan ──
            # NOTE: Phases run SEQUENTIALLY to keep peak RAM under 512MB on Render.
            # Only one Nuclei subprocess runs at a time (150-300MB each).
            phase1_tags = "exposure,default-login,takeover,env,auth"
            phase1_paths = self._find_matching_templates(
                # Narrowed to highest-signal folders only
                ["http/exposures", "http/default-logins", "http/takeovers"],
                phase1_tags,
                max_results=MAX_TEMPLATES_PER_PHASE
            )

            all_results = []
            if phase1_paths:
                r1 = await self._run_nuclei_single(base_targets, phase1_tags, phase1_paths)
                all_results.extend(r1)
            else:
                logger.info("[Nuclei] No matching Phase 1 templates found. Skipping Phase 1.")

            # ── Phase 2: Technology-specific vulnerability scan ──
            VALID_TECH_TAGS = {
                "nginx", "apache", "iis", "php", "laravel", "wordpress", "joomla",
                "drupal", "django", "flask", "express", "nodejs", "node", "react",
                "nextjs", "next.js", "angular", "vue", "nuxt", "tomcat", "spring",
                "struts", "rails", "ruby", "asp.net", "dotnet", "java", "jenkins",
                "grafana", "kibana", "elasticsearch", "redis", "mongodb", "mysql",
                "postgres", "mssql", "oracle", "docker", "kubernetes", "gitlab",
                "bitbucket", "confluence", "jira", "sonarqube", "rabbitmq",
                "apache-http-server", "litespeed", "caddy", "openresty", "varnish",
                "shopify", "magento", "prestashop", "woocommerce", "webflow",
                "cloudflare", "fastly", "akamai", "aws", "azure", "gcp",
                "minio", "adminer", "phpmyadmin", "wp-admin",
            }
            tech_tags_filtered = [t for t in tags if t in VALID_TECH_TAGS]
            if tech_tags_filtered:
                phase2_tags = ",".join(tech_tags_filtered)
                # http/technologies only — http/cves has thousands of templates and is far too slow
                phase2_paths = self._find_matching_templates(
                    ["http/technologies"],
                    phase2_tags,
                    max_results=MAX_TEMPLATES_PER_PHASE
                )
                if phase2_paths:
                    r2 = await self._run_nuclei_single(base_targets, phase2_tags, phase2_paths)
                    all_results.extend(r2)
                else:
                    logger.info(f"[Nuclei] No matching Phase 2 templates. Skipping Phase 2.")
            else:
                logger.info("[Nuclei] No tech tags matched. Skipping Phase 2.")

            # ── Phase 3: DAST — only if explicitly requested ──
            dast_keywords = {"dast", "sqli", "xss", "lfi", "idor"}
            if any(t.lower() in dast_keywords for t in tags):
                phase3_tags = "dast,sqli,xss,lfi,idor"
                phase3_paths = self._find_matching_templates(
                    ["dast"],
                    phase3_tags,
                    max_results=40  # DAST is heavy — keep this very low
                )
                if phase3_paths:
                    r3 = await self._run_nuclei_single(targets, phase3_tags, phase3_paths, is_dast=True)
                    all_results.extend(r3)
                else:
                    logger.info("[Nuclei] No matching Phase 3 templates found. Skipping Phase 3.")
            else:
                logger.info("[Nuclei] DAST tags not explicitly requested. Skipping Phase 3.")

            # Deduplicate by template_id + matched_at
            seen = set()
            for r in all_results:
                key = (r.get("template_id", ""), r.get("matched_at", ""))
                if key not in seen:
                    seen.add(key)
                    results.append(r)

            # Post-process to filter out catch-all false positives
            results = await self._filter_catch_all_findings(results)

            return results

    async def _run_nuclei_single(self, targets: list[str], tags: str, template_paths: list[str], is_dast: bool = False) -> list[dict]:
        """Run a single Nuclei invocation with all templates at once (no batching)."""
        if not template_paths or not targets:
            return []

        import tempfile

        temp_dir = self.base_dir / "tmp"
        temp_dir.mkdir(exist_ok=True)

        fd_targets, targets_file = tempfile.mkstemp(suffix="_nuclei_targets.txt", dir=str(temp_dir))
        fd_templates, templates_file = tempfile.mkstemp(suffix="_nuclei_tpls.txt", dir=str(temp_dir))

        try:
            with os.fdopen(fd_targets, 'w', encoding='utf-8') as f:
                for t in targets:
                    f.write(f"{t}\n")

            with os.fdopen(fd_templates, 'w', encoding='utf-8') as f:
                for p in template_paths:
                    f.write(f"{p.replace(chr(92), '/')}\n")

            return await self._run_nuclei(targets_file, tags, templates_file, is_dast)
        finally:
            for path in [targets_file, templates_file]:
                try:
                    os.remove(path)
                except Exception:
                    pass

    async def _filter_catch_all_findings(self, findings: list[dict]) -> list[dict]:
        """Post-process findings to remove false positives caused by path or subdomain catch-alls."""
        import httpx
        import uuid
        from urllib.parse import urlparse

        async def verify_finding(finding: dict):
            matched_url = finding.get("matched_at", "")
            if not matched_url or not matched_url.startswith("http"):
                return finding
                
            parsed = urlparse(matched_url)
            
            try:
                async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(connect=2.0, read=4.0, write=2.0, pool=2.0)) as client:
                    # 1. Check Path Catch-All
                    if parsed.path and parsed.path != "/":
                        random_path = uuid.uuid4().hex
                        catch_all_url = f"{parsed.scheme}://{parsed.netloc}/{random_path}"
                        try:
                            resp, catch_all_resp = await asyncio.gather(
                                client.get(matched_url, follow_redirects=False),
                                client.get(catch_all_url, follow_redirects=False)
                            )
                            if resp.status_code == catch_all_resp.status_code:
                                len1, len2 = len(resp.text), len(catch_all_resp.text)
                                if max(len1, len2) > 0 and abs(len1 - len2) / max(len1, len2) < 0.10:
                                    logger.info(f"[Nuclei/PostCheck] Filtered {finding.get('template_id')} at {matched_url} — PATH catch-all.")
                                    return None
                        except Exception as e:
                            logger.debug(f"[Nuclei/PostCheck] Path check failed for {matched_url}: {e}")
                    
                    # 2. Check Subdomain Catch-All (Wildcard DNS)
                    parts = parsed.netloc.split('.')
                    if len(parts) > 2 and not parts[-1].isdigit():
                        random_sub = uuid.uuid4().hex[:8]
                        wildcard_netloc = f"{random_sub}.{'.'.join(parts[1:])}"
                        wildcard_url = f"{parsed.scheme}://{wildcard_netloc}{parsed.path}"
                        try:
                            resp, wildcard_resp = await asyncio.gather(
                                client.get(matched_url, follow_redirects=False),
                                client.get(wildcard_url, follow_redirects=False)
                            )
                            if resp.status_code == wildcard_resp.status_code:
                                len1, len2 = len(resp.text), len(wildcard_resp.text)
                                if max(len1, len2) > 0 and abs(len1 - len2) / max(len1, len2) < 0.10:
                                    logger.info(f"[Nuclei/PostCheck] Filtered {finding.get('template_id')} at {matched_url} — SUBDOMAIN catch-all.")
                                    return None
                        except Exception as e:
                            logger.debug(f"[Nuclei/PostCheck] Subdomain check failed for {matched_url}: {e}")
            except Exception as e:
                logger.debug(f"[Nuclei/PostCheck] Client error for {matched_url}: {e}")
                    
            return finding

        verified_results = await asyncio.gather(*[verify_finding(f) for f in findings])
        return [r for r in verified_results if r]

    async def _run_nuclei(self, targets_file: str, tags: str, templates_file: str, is_dast: bool = False) -> list[dict]:
        """Run a single Nuclei subprocess invocation."""
        results = []

        cmd = [
            str(self.nuclei_bin).replace(chr(92), '/'),
            "-list", targets_file.replace(chr(92), '/'),
            "-tl", templates_file.replace(chr(92), '/'),
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-ni",
            "-no-stdin",
            "-mhe", "3",
            "-severity", "info,low,medium,high,critical",
            "-timeout", "3",
            "-retries", "0",       # No retries — speed is priority
            "-bulk-size", "25",
            "-rate-limit", "100",
            "-c", "25",
            "-rsr", "524288",      # 512KB response size cap
        ]

        if is_dast:
            cmd.append("-dast")

        try:
            logger.info(f"[Nuclei] Running scan | tags={tags} | templates={templates_file}")

            def run_nuclei():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=NUCLEI_BATCH_TIMEOUT
                )

            process = await asyncio.to_thread(run_nuclei)

            if process.stdout:
                for line in process.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        results.append({
                            "cve_id": data.get("matcher-name") or info.get("name", "Unknown Issue"),
                            "severity": info.get("severity", "info"),
                            "description": info.get("description", "Verified by Nuclei"),
                            "extracted_results": data.get("extracted-results", []),
                            "matched_at": data.get("matched-at"),
                            "template_id": data.get("template-id"),
                            "curl_command": data.get("curl-command")
                        })
                    except json.JSONDecodeError:
                        pass

            if process.stderr:
                for line in process.stderr.strip().splitlines():
                    if any(lvl in line for lvl in ["[ERR]", "[FTL]"]):
                        logger.warning(f"Nuclei error: {line}")
                    else:
                        logger.debug(f"Nuclei: {line}")

        except subprocess.TimeoutExpired:
            logger.warning(f"[Nuclei] Scan timed out after {NUCLEI_BATCH_TIMEOUT}s for tags={tags}")
        except Exception:
            logger.exception("[Nuclei] Scan execution failed")

        return results
