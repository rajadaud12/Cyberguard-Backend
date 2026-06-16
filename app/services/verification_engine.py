import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class NucleiVerificationEngine:
    def __init__(self):
        self.nuclei_bin = Path("bin/nuclei.exe").absolute()
        if not self.nuclei_bin.exists():
            logger.warning(f"Nuclei binary not found at {self.nuclei_bin}")

    async def verify(self, target_url: str | list[str], tags: list[str]) -> list[dict]:
        if not self.nuclei_bin.exists():
            return []

        results = []

        # Normalize targets: scan each URL individually for multi-port hosts
        if isinstance(target_url, list):
            targets = target_url
        else:
            targets = [target_url]

        # ── Phase 1: Broad exposure/misconfig scan (high-signal, fast) ──
        # These tag categories reliably catch .env leaks, exposed panels,
        # default credentials, misconfigurations, and takeover opportunities.
        phase1_tags = "exposure,misconfig,default-login,takeover,config,env,file"

        # ── Phase 2: Technology-specific vulnerability scan ──
        # Use tech-stack detected tags to run targeted CVE/vuln templates.
        # Filter out garbage tags that would match nothing.
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

        all_results = []
        for target in targets:
            # Phase 1: exposure/misconfig scan
            r1 = await self._run_nuclei(target, phase1_tags)
            all_results.extend(r1)

            # Phase 2: tech-specific scan (only if we have relevant tags)
            if tech_tags_filtered:
                phase2_tags = ",".join(tech_tags_filtered)
                r2 = await self._run_nuclei(target, phase2_tags)
                all_results.extend(r2)

        # Deduplicate by template_id + matched_at
        seen = set()
        for r in all_results:
            key = (r.get("template_id", ""), r.get("matched_at", ""))
            if key not in seen:
                seen.add(key)
                results.append(r)

        return results

    async def _run_nuclei(self, target: str, tags: str) -> list[dict]:
        """Run a single Nuclei scan against a target with given tags."""
        results = []

        cmd = [
            str(self.nuclei_bin),
            "-u", target,
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",           # Disable update checks which can hang
            "-tags", tags,
            "-severity", "info,low,medium,high,critical",
            "-timeout", "10",  # Per-request timeout in seconds
            "-retries", "1",
            "-bulk-size", "50",
            "-rate-limit", "100",
        ]

        try:
            logger.info(f"Running Nuclei on {target} with tags: {tags}")

            def run_nuclei():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=300  # Hard timeout of 5 minutes per run
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
            logger.warning(f"Nuclei timed out for {target} with tags {tags}")
        except Exception as e:
            logger.exception(f"Nuclei execution failed for {target}")

        return results
