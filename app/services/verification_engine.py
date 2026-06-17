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

    def _find_matching_templates(self, folders: list[str], tags: str) -> list[str]:
        matching_paths = []
        if not self.templates_dir.exists() or not tags:
            return []
            
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
        if not tag_list:
            return []
            
        tag_set = set(tag_list)
        
        # Avoid loading thousands of files if possible
        import os
        import re
        tags_re = re.compile(r'^\s*tags:\s*(.+)$', re.MULTILINE)
        max_req_re = re.compile(r'max-request:\s*(\d+)', re.IGNORECASE)
        
        for folder in folders:
            folder_path = self.templates_dir / folder
            if not folder_path.exists():
                continue
                
            for root, _, files in os.walk(folder_path):
                for file in files:
                    if file.endswith(".yaml") or file.endswith(".yml"):
                        file_path = os.path.join(root, file)
                        try:
                            # Read first 1500 chars (fast pre-filter)
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                head = f.read(1500).lower()
                                
                                # Skip heavy brute force/directory fuzzing templates
                                max_req_match = max_req_re.search(head)
                                if max_req_match:
                                    if int(max_req_match.group(1)) > 50:
                                        continue
                                        
                                match = tags_re.search(head)
                                if match:
                                    raw_tags = match.group(1).strip().strip('"\'[]{}')
                                    template_tags = {t.strip().lower() for t in raw_tags.split(",") if t.strip()}
                                    if tag_set.intersection(template_tags):
                                        matching_paths.append(file_path)
                                else:
                                    # Fallback to simple substring match if tags regex failed to match but 'tags:' is present
                                    if "tags:" in head and any(t in head for t in tag_set):
                                        matching_paths.append(file_path)
                        except Exception:
                            pass
        logger.info(f"[Nuclei] Pre-filtered templates for folders {folders} and tags {tags}: found {len(matching_paths)} matches")
        return matching_paths

    async def _filter_active_targets(self, targets: list[str]) -> list[str]:
        """Verify that target URLs are responsive before passing them to Nuclei to prevent hangs."""
        import httpx
        
        active_targets = []
        async def check_target(url: str):
            try:
                # Use a short connect/read timeout to check responsiveness
                async with httpx.AsyncClient(verify=False, timeout=2.5) as client:
                    await client.get(url, follow_redirects=False)
                    return url
            except Exception as e:
                logger.warning(f"[Nuclei/PreCheck] Target {url} is unresponsive (skipped): {e}")
                return None

        # Run checks in parallel
        tasks = [check_target(t) for t in targets]
        results = await asyncio.gather(*tasks)
        active_targets = [r for r in results if r]
        
        logger.info(f"[Nuclei/PreCheck] Filtered targets: {len(targets)} input -> {len(active_targets)} active")
        return active_targets

    async def verify(self, target_url: str | list[str], tags: list[str]) -> list[dict]:
        if not self.nuclei_bin.exists():
            logger.error("Nuclei binary not found. Skipping verification.")
            return []

        async with _NUCLEI_SEM:
            results = []

            # Normalize targets: scan each URL individually for multi-port hosts
            if isinstance(target_url, list):
                targets = target_url
            else:
                targets = [target_url]

            if not targets:
                return []

            # Filter out unresponsive targets to prevent Nuclei from hanging/timing out on dead/filtered ports
            targets = await self._filter_active_targets(targets)
            if not targets:
                logger.info("[Nuclei/PreCheck] No responsive targets found. Skipping verification.")
                return []

            # ── Phase 1: Broad exposure/misconfig scan (high-signal, fast) ──
            phase1_tags = "exposure,default-login,takeover,env"
            phase1_paths = self._find_matching_templates(
                ["http/exposures", "http/default-logins", "http/exposed-panels", "http/takeovers"],
                phase1_tags
            )
            
            all_results = []
            if phase1_paths:
                r1 = await self._run_nuclei_batch(targets, phase1_tags, phase1_paths)
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
                phase2_paths = self._find_matching_templates(
                    ["http/technologies", "http/cves"],
                    phase2_tags
                )
                
                if phase2_paths:
                    r2 = await self._run_nuclei_batch(targets, phase2_tags, phase2_paths)
                    all_results.extend(r2)
                else:
                    logger.info(f"[Nuclei] No matching Phase 2 templates found for tags {phase2_tags}. Skipping Phase 2.")

            # Deduplicate by template_id + matched_at
            seen = set()
            for r in all_results:
                key = (r.get("template_id", ""), r.get("matched_at", ""))
                if key not in seen:
                    seen.add(key)
                    results.append(r)

            return results

    async def _run_nuclei_batch(self, targets: list[str], tags: str, template_paths: list[str]) -> list[dict]:
        """Run Nuclei scans against targets by batching templates in groups of 100 to prevent OOM."""
        if not template_paths:
            return []

        import tempfile

        # Ensure temp directory exists under backend root or uses system temp safely
        temp_dir = self.base_dir / "tmp"
        temp_dir.mkdir(exist_ok=True)

        fd, temp_file_path = tempfile.mkstemp(suffix="_nuclei_targets.txt", dir=str(temp_dir))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            # Batch template paths in groups of 100 to prevent OOM on Render
            TEMPLATE_BATCH_SIZE = 100
            template_batches = [template_paths[i:i + TEMPLATE_BATCH_SIZE] for i in range(0, len(template_paths), TEMPLATE_BATCH_SIZE)]
            
            results = []
            for idx, batch_paths in enumerate(template_batches):
                fd_t, temp_templates_path = tempfile.mkstemp(suffix=f"_nuclei_templates_b{idx}.txt", dir=str(temp_dir))
                try:
                    with os.fdopen(fd_t, 'w', encoding='utf-8') as f_t:
                        for path in batch_paths:
                            f_t.write(f"{path}\n")
                    
                    batch_results = await self._run_nuclei(temp_file_path, tags, temp_templates_path)
                    results.extend(batch_results)
                finally:
                    try:
                        os.remove(temp_templates_path)
                    except Exception:
                        pass
                        
            return results
        finally:
            try:
                os.remove(temp_file_path)
            except Exception:
                pass

    async def _run_nuclei(self, targets_file: str, tags: str, templates_file: str) -> list[dict]:
        """Run Nuclei command line tool using a targets file and a templates list file input."""
        results = []

        cmd = [
            str(self.nuclei_bin),
            "-list", targets_file,
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",             # Disable update checks which can hang
            "-ni",              # Disable Interactsh (OAST) to prevent polling delays/hangs
            "-no-stdin",        # Disable stdin processing to prevent hanging in background
            "-mhe", "5",        # Max host errors before skipping host to save time
            "-tags", tags,
            "-severity", "info,low,medium,high,critical",
            "-timeout", "3",    # Per-request timeout in seconds (optimized down from 5)
            "-retries", "1",
            "-bulk-size", "25",  # Concurrency settings optimized for speed and memory safety
            "-rate-limit", "150",
            "-c", "25",
            "-rsr", "1048576"   # Limit response size read to 1MB to save RAM buffers
        ]

        if templates_file:
            cmd.extend(["-t", templates_file])

        try:
            logger.info(f"Running Nuclei batch scan with tags: {tags}")

            def run_nuclei():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=300  # Hard timeout of 5 minutes per run (increased from 180s)
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
                err = process.stderr.strip()
                if err:
                    # Only log real errors, not info/progress lines
                    for line in err.splitlines():
                        if any(lvl in line for lvl in ["[ERR]", "[FTL]"]):
                            logger.warning(f"Nuclei error: {line}")
                        else:
                            logger.debug(f"Nuclei: {line}")

        except subprocess.TimeoutExpired:
            logger.warning(f"Nuclei batch timed out for tags {tags}")
        except Exception as e:
            logger.exception("Nuclei batch execution failed")

        return results
