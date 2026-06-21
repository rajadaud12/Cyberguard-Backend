"""
CyberGuard -- EASM Router
External Attack Surface Management: domains, IPs, ports, certificates.
All data is read from the DB (populated by easm_scanner.py).
"""
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, Query, HTTPException
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi_cache.decorator import cache
from app.cache_utils import tenant_key_builder

from app.dependencies import get_db, get_current_user, require_admin
from app.database import set_rls_tenant
from app.models.user import User
from app.models.scope import ScanScope
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.services.easm_scanner import run_easm_scan

router = APIRouter(prefix="/api/v1/easm", tags=["EASM"])


# ── helpers ────────────────────────────────────────────────────────────────────

def _asset_to_dict(a: EasmAsset, findings: list = None) -> dict:
    import json
    parsed_stack = []
    for item in (a.tech_stack or []):
        try:
            obj = json.loads(item)
            if obj.get("version"):
                parsed_stack.append(f"{obj['name']} {obj['version']}")
            else:
                parsed_stack.append(obj["name"])
        except json.JSONDecodeError:
            parsed_stack.append(item)

    return {
        "id": str(a.id),
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "http_status": a.http_status,
        "asset_type": a.asset_type,
        "tech_stack": parsed_stack,
        "sec_headers_grade": a.sec_headers_grade,
        "cve_count": a.cve_count,
        "status": a.status,
        "is_catch_all": a.is_catch_all,
        "is_exposed_admin": a.is_exposed_admin,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "issues": findings or [],
    }


def _port_to_dict(p: EasmPort) -> dict:
    return {
        "ip": p.ip_address,
        "port": p.port,
        "protocol": p.protocol,
        "service": p.service or "",
        "banner": p.banner or "",
        "risk": p.risk_level,
        "is_risky": p.is_risky,
        "provider": p.provider or "Unknown",
        "location": p.location or "Unknown",
    }


def _cert_to_dict(c: EasmCertificate) -> dict:
    return {
        "hostname": c.hostname,
        "issuer": c.issuer or "Unknown",
        "valid_from": c.valid_from.isoformat() if c.valid_from else None,
        "valid_to": c.valid_to.isoformat() if c.valid_to else None,
        "is_expired": c.is_expired,
        "is_self_signed": c.is_self_signed,
        "is_mismatch": getattr(c, "is_mismatch", False),
        "days_to_expiry": c.days_to_expiry,
        "sans": c.sans or [],
    }


# ── endpoints ──────────────────────────────────────────────────────────────────

@router.get("/overview")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_easm_overview(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Get high-level dashboard metrics for the EASM Hub."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    tenant_id = current_user.tenant_id
    from sqlalchemy import case, cast, Integer, String
    import asyncio
    from app.database import get_tenant_db

    async def fetch_assets():
        async with get_tenant_db(str(tenant_id)) as db:
            res = await db.execute(
                select(
                    func.count(EasmAsset.id).label("total_domains"),
                    func.sum(cast(EasmAsset.http_status == 200, Integer)).label("live_servers"),
                    func.sum(cast(EasmAsset.is_catch_all == True, Integer)).label("catch_all"),
                    func.sum(cast(EasmAsset.is_exposed_admin == True, Integer)).label("exposed_admin"),
                    func.sum(cast(and_(EasmAsset.http_status == 200, EasmAsset.asset_type == "web"), Integer)).label("website_count")
                ).where(EasmAsset.tenant_id == tenant_id)
            )
            return res.first()

    async def fetch_ports():
        async with get_tenant_db(str(tenant_id)) as db:
            res = await db.execute(
                select(
                    func.count(EasmPort.id).label("total_ports"),
                    func.sum(cast(EasmPort.is_risky == True, Integer)).label("risky_ports"),
                    func.count(func.distinct(EasmPort.ip_address)).label("total_ips")
                ).where(EasmPort.tenant_id == tenant_id)
            )
            return res.first()

    async def fetch_certs():
        async with get_tenant_db(str(tenant_id)) as db:
            res = await db.execute(
                select(
                    func.count(EasmCertificate.id).label("total_certs"),
                    func.sum(cast(EasmCertificate.is_expired == True, Integer)).label("expired_certs"),
                    func.sum(cast(and_(EasmCertificate.is_expired == False, EasmCertificate.days_to_expiry <= 30, EasmCertificate.days_to_expiry >= 0), Integer)).label("expiring_soon")
                ).where(EasmCertificate.tenant_id == tenant_id)
            )
            return res.first()

    async def fetch_findings():
        async with get_tenant_db(str(tenant_id)) as db:
            res = await db.execute(
                select(cast(Finding.severity, String), func.count()).where(
                    and_(Finding.tenant_id == tenant_id, Finding.status == "open")
                ).group_by(cast(Finding.severity, String))
            )
            return {row[0]: row[1] for row in res.all()}

    asset_counts, port_counts, cert_counts, severity_counts = await asyncio.gather(
        fetch_assets(), fetch_ports(), fetch_certs(), fetch_findings()
    )

    total_domains = asset_counts.total_domains or 0 if asset_counts else 0
    live_servers = asset_counts.live_servers or 0 if asset_counts else 0
    catch_all = asset_counts.catch_all or 0 if asset_counts else 0
    exposed_admin = asset_counts.exposed_admin or 0 if asset_counts else 0
    website_count = asset_counts.website_count or 0 if asset_counts else 0

    total_ports = port_counts.total_ports or 0 if port_counts else 0
    risky_ports = port_counts.risky_ports or 0 if port_counts else 0
    total_ips = port_counts.total_ips or 0 if port_counts else 0

    total_certs = cert_counts.total_certs or 0 if cert_counts else 0
    expired_certs = cert_counts.expired_certs or 0 if cert_counts else 0
    expiring_soon = cert_counts.expiring_soon or 0 if cert_counts else 0
    
    critical_vulns = severity_counts.get("critical", 0)
    high_vulns = severity_counts.get("high", 0)
    medium_vulns = severity_counts.get("medium", 0)
    low_vulns = severity_counts.get("low", 0)
    total_vulns = critical_vulns + high_vulns + medium_vulns + low_vulns

    # Simple Posture Score calculation (starts at 100)
    # Deductions: Critical=10, High=5, Medium=2, Low=1
    score = 100 - (critical_vulns * 10) - (high_vulns * 5) - (medium_vulns * 2) - (low_vulns * 1)
    posture_score = max(0, min(100, score))
    if posture_score >= 90:
        grade = "A Grade"
    elif posture_score >= 80:
        grade = "B Grade"
    elif posture_score >= 70:
        grade = "C Grade"
    elif posture_score >= 60:
        grade = "D Grade"
    else:
        grade = "F Grade"

    # ── Calculate top providers/technologies dynamically ──
    from collections import Counter
    import json
    import dns.asyncresolver

    # 1. Top Web Technologies/Hosts
    web_tech_counter = Counter()
    async with get_tenant_db(str(tenant_id)) as db:
        res = await db.execute(
            select(EasmAsset.tech_stack).where(
                and_(
                    EasmAsset.tenant_id == tenant_id,
                    EasmAsset.asset_type == "web",
                    EasmAsset.http_status == 200
                )
            )
        )
        for row in res.scalars().all():
            for item in (row or []):
                try:
                    obj = json.loads(item)
                    web_tech_counter[obj["name"]] += 1
                except Exception:
                    web_tech_counter[item] += 1
    
    FAMOUS_FRAMEWORKS = {
        "next.js", "node.js", "react", "vue.js", "angular", "nuxt.js", "laravel", 
        "django", "ruby on rails", "express", "svelte", "wordpress", "gatsby", "astro"
    }
    sorted_techs = sorted(
        web_tech_counter.items(),
        key=lambda x: (0 if x[0].lower() in FAMOUS_FRAMEWORKS else 1, -x[1])
    )
    top_web_techs = [tech for tech, _ in sorted_techs[:4]]

    # 2. Top Email Providers (detect MX/SPF from scopes)
    async def detect_email_provider(domain: str) -> str:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.0
        try:
            answers = await resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_host = rdata.exchange.to_text().lower()
                if "outlook" in mx_host or "pphosted" in mx_host or "microsoft" in mx_host:
                    return "Microsoft 365"
                if "google" in mx_host or "asmtp" in mx_host:
                    return "Google Workspace"
                if "mimecast" in mx_host:
                    return "Mimecast"
                if "zoho" in mx_host:
                    return "Zoho Mail"
        except Exception:
            pass
        try:
            answers = await resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = "".join([s.decode('utf-8') for s in rdata.strings])
                if txt.startswith("v=spf1"):
                    if "outlook.com" in txt or "protection.outlook.com" in txt:
                        return "Microsoft 365"
                    if "_spf.google.com" in txt or "google.com" in txt:
                        return "Google Workspace"
                    if "mimecast.com" in txt:
                        return "Mimecast"
                    if "zoho.com" in txt:
                        return "Zoho Mail"
        except Exception:
            pass
        return "Custom Mail"

    scopes_result = await session.execute(
        select(ScanScope.value).where(
            and_(ScanScope.tenant_id == tenant_id, ScanScope.type == "domain")
        )
    )
    root_domains = [s.lower().strip() for s in scopes_result.scalars().all()]
    
    email_providers_set = set()
    if root_domains:
        tasks = [detect_email_provider(d) for d in root_domains[:5]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                email_providers_set.add(r)
    top_email_providers = list(email_providers_set)[:4]

    # 3. Top Infrastructure Providers (ISPs/ASNs from EasmPort)
    def clean_infra_provider(name: str) -> str:
        name_lower = name.lower()
        if "amazon" in name_lower or "aws" in name_lower:
            return "AWS"
        if "cloudflare" in name_lower:
            return "Cloudflare"
        if "digitalocean" in name_lower or "digital ocean" in name_lower:
            return "DigitalOcean"
        if "google" in name_lower:
            return "Google Cloud"
        if "microsoft" in name_lower or "azure" in name_lower:
            return "Azure"
        if "ovh" in name_lower:
            return "OVH"
        if "linode" in name_lower or "akamai" in name_lower:
            return "Linode"
        parts = name.split()
        return " ".join(parts[:2])

    infra_counter = Counter()
    async with get_tenant_db(str(tenant_id)) as db:
        res = await db.execute(
            select(EasmPort.provider)
            .where(
                and_(
                    EasmPort.tenant_id == tenant_id,
                    EasmPort.provider != None,
                    EasmPort.provider != "Unknown"
                )
            )
        )
        for prov in res.scalars().all():
            infra_counter[clean_infra_provider(prov)] += 1
            
    top_infra_providers = [prov for prov, _ in infra_counter.most_common(4)]

    # Category counts
    # website_count is calculated above
    infra_count = total_ips
    
    brand_email_issues = await session.scalar(
        select(func.count(Finding.id)).where(
            and_(
                Finding.tenant_id == current_user.tenant_id,
                Finding.status != "false_positive",
                Finding.issue_type.in_([
                    "Missing DMARC Record", 
                    "DMARC Policy is 'None'", 
                    "Missing SPF Record"
                ])
            )
        )
    ) or 0

    return {
        "total_domains": total_domains,
        "new_domains_week": 0,
        "live_web_servers": live_servers,
        "catch_all_count": catch_all,
        "exposed_admin_count": exposed_admin,
        "exposed_admin_critical": min(exposed_admin, 1),
        "total_ips": total_ips,
        "total_ports": total_ports,
        "risky_ports": risky_ports,
        "total_certificates": total_certs,
        "expired_certificates": expired_certs,
        "expiring_soon": expiring_soon,
        "brand_email_issues": brand_email_issues,
        "scan_pending": total_domains == 0,
        
        # New overview metrics
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": critical_vulns,
        "total_assets_detected": total_domains + total_ips,
        "posture_score": posture_score,
        "posture_grade": grade,
        "total_subdomains": total_domains,  # all assets are treated as subdomains/hosts
        
        # Categories
        "categories": {
            "websites": {
                "total": website_count, 
                "vulnerabilities": high_vulns + medium_vulns,
                "providers": top_web_techs
            },
            "emails": {
                "total": len(root_domains), 
                "vulnerabilities": brand_email_issues,
                "providers": top_email_providers
            },
            "identities": {
                "total": 0, 
                "vulnerabilities": 0,
                "providers": []
            },
            "infrastructure": {
                "total": infra_count, 
                "vulnerabilities": critical_vulns + high_vulns,
                "providers": top_infra_providers
            },
        }
    }

@router.get("/recent-hits")
async def get_easm_recent_hits(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Latest 5 findings from the scanner."""
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    q = select(Finding).where(
        and_(Finding.tenant_id == current_user.tenant_id, Finding.status == "open", Finding.source == "ext_scanner")
    ).order_by(Finding.created_at.desc()).limit(5)
    
    result = await session.execute(q)
    findings = result.scalars().all()
    
    hits = []
    for f in findings:
        hits.append({
            "id": str(f.id),
            "date_found": f.created_at.isoformat() if f.created_at else None,
            "issue_type": f.issue_type,
            "asset": f.entity,
            "asset_type": "Domain" if ":" not in f.entity else "IPV4",
            "severity": f.severity,
        })
    return {"hits": hits}


@router.get("/ips")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_easm_ips(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    """Paginated IP inventory with provider, location, and associated data."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    import asyncio
    from app.database import get_tenant_db

    async def fetch_total():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            total_q = select(func.count(func.distinct(EasmPort.ip_address))).where(
                EasmPort.tenant_id == current_user.tenant_id
            )
            return await db.scalar(total_q) or 0

    async def fetch_ips():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            ip_q = select(EasmPort.ip_address).where(
                EasmPort.tenant_id == current_user.tenant_id
            ).group_by(EasmPort.ip_address).order_by(
                func.count(EasmPort.id).desc(), EasmPort.ip_address
            ).offset((page - 1) * per_page).limit(per_page)
            res = await db.execute(ip_q)
            return list(res.scalars().all())

    total, target_ips = await asyncio.gather(fetch_total(), fetch_ips())

    if not target_ips:
        return {"ips": [], "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}

    # Fetch ONLY the ports and hostnames for the target IPs
    q = select(EasmPort, EasmAsset.hostname).outerjoin(
        EasmAsset, EasmPort.asset_id == EasmAsset.id
    ).where(
        and_(
            EasmPort.tenant_id == current_user.tenant_id,
            EasmPort.ip_address.in_(target_ips)
        )
    )
    
    result = await session.execute(q)
    rows = result.all()
    
    # Aggregate by IP
    ips_map = {}
    for port, hostname in rows:
        ip = port.ip_address
        if ip not in ips_map:
            ips_map[ip] = {
                "ip": ip,
                "provider": port.provider or "Unknown",
                "location": port.location or "Unknown",
                "associated_hostnames": set(),
                "open_ports": [],
            }
        
        if hostname:
            ips_map[ip]["associated_hostnames"].add(hostname)
        
        # Add port details
        port_detail = {
            "port": port.port,
            "protocol": port.protocol,
            "service": port.service,
            "risk": port.risk_level,
            "is_risky": port.is_risky
        }
        # prevent duplicates if same port is recorded multiple times
        if not any(p["port"] == port.port for p in ips_map[ip]["open_ports"]):
            ips_map[ip]["open_ports"].append(port_detail)

    # Convert sets to lists and preserve the original sorting order
    ip_list = []
    for ip in target_ips:
        if ip in ips_map:
            data = ips_map[ip]
            data["associated_hostnames"] = list(data["associated_hostnames"])
            data["open_ports"] = sorted(data["open_ports"], key=lambda p: p["port"])
            ip_list.append(data)

    return {
        "ips": ip_list,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
    }


@router.get("/assets")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_easm_assets(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
):
    """Paginated domain/asset inventory from DB."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    from app.models.scope import ScanScope
    scopes_result = await session.execute(
        select(ScanScope.value).where(
            and_(ScanScope.tenant_id == current_user.tenant_id, ScanScope.type == "domain")
        )
    )
    root_domains = scopes_result.scalars().all()

    # Only show base domains in the /assets (Domains) tab
    if not root_domains:
        q = select(EasmAsset).where(False)
    else:
        q = select(EasmAsset).where(
            and_(
                EasmAsset.tenant_id == current_user.tenant_id,
                EasmAsset.hostname.in_(root_domains)
            )
        )

    if search:
        q = q.where(EasmAsset.hostname.ilike(f"%{search}%"))
    if asset_type and asset_type != "all":
        q = q.where(EasmAsset.asset_type == asset_type)

    import asyncio
    from app.database import get_tenant_db

    async def fetch_total():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            return await db.scalar(select(func.count(EasmAsset.id)).where(q.whereclause)) or 0

    async def fetch_page():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            page_q = q.order_by(EasmAsset.hostname).offset((page - 1) * per_page).limit(per_page)
            res = await db.execute(page_q)
            return res.scalars().all()

    total, assets = await asyncio.gather(fetch_total(), fetch_page())

    from collections import defaultdict
    from app.models.finding import Finding
    findings_map = defaultdict(list)
    if assets:
        hostnames = [a.hostname for a in assets]
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            findings_q = select(Finding.entity, Finding.issue_type, Finding.severity).where(
                and_(
                    Finding.tenant_id == current_user.tenant_id,
                    Finding.status == "open",
                    Finding.entity.in_(hostnames)
                )
            )
            findings_res = await db.execute(findings_q)
            for entity, issue_type, severity in findings_res.all():
                findings_map[entity].append({"issue_type": issue_type, "severity": severity})

    return {
        "assets": [_asset_to_dict(a, findings_map.get(a.hostname, [])) for a in assets],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
        "scan_pending": total == 0,
    }


@router.get("/ports")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_easm_ports(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    risky_only: bool = Query(False),
):
    """Paginated port inventory from DB."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    q = select(EasmPort).where(EasmPort.tenant_id == current_user.tenant_id)
    if risky_only:
        q = q.where(EasmPort.is_risky == True)

    import asyncio
    from app.database import get_tenant_db

    async def fetch_total():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            return await db.scalar(select(func.count(EasmPort.id)).where(q.whereclause)) or 0

    async def fetch_page():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            page_q = q.order_by(EasmPort.is_risky.desc(), EasmPort.port).offset((page - 1) * per_page).limit(per_page)
            res = await db.execute(page_q)
            return res.scalars().all()

    total, ports = await asyncio.gather(fetch_total(), fetch_page())

    return {
        "ports": [_port_to_dict(p) for p in ports],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
    }


@router.get("/certificates")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_easm_certificates(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    await set_rls_tenant(session, str(current_user.tenant_id))

    q = select(EasmCertificate).where(EasmCertificate.tenant_id == current_user.tenant_id)
    import asyncio
    from app.database import get_tenant_db

    async def fetch_total():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            return await db.scalar(select(func.count(EasmCertificate.id)).where(q.whereclause)) or 0

    async def fetch_page():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            page_q = q.order_by(EasmCertificate.is_expired.desc(), EasmCertificate.days_to_expiry).offset((page - 1) * per_page).limit(per_page)
            res = await db.execute(page_q)
            return res.scalars().all()

    total, certs = await asyncio.gather(fetch_total(), fetch_page())

    return {
        "certificates": [_cert_to_dict(c) for c in certs],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
    }


@router.get("/brand-email")
async def get_easm_brand_email(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """DMARC / DKIM / SPF brand and email security issues."""
    from app.models.finding import Finding
    from sqlalchemy import select, and_
    
    q = select(Finding).where(
        and_(
            Finding.tenant_id == current_user.tenant_id,
            Finding.status != "false_positive",
            Finding.issue_type.in_([
                "Missing DMARC Record", 
                "DMARC Policy is 'None'", 
                "Missing SPF Record"
            ])
        )
    )
    result = await session.execute(q)
    findings = result.scalars().all()
    
    issues = []
    for f in findings:
        issues.append({
            "type": f.issue_type,
            "domain": f.entity,
            "issue": f.evidence.get("description", f.issue_type),
            "severity": f.severity
        })
        
    return {"issues": issues, "total": len(issues), "scan_pending": False}


@router.get("/subdomains")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_easm_subdomains(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
):
    """
    Paginated subdomain inventory.
    Returns all discovered hosts (subdomains + root domains) from EASM assets.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    q = select(EasmAsset).where(EasmAsset.tenant_id == current_user.tenant_id)
    if search:
        q = q.where(EasmAsset.hostname.ilike(f"%{search}%"))

    import asyncio
    from app.database import get_tenant_db

    async def fetch_total():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            return await db.scalar(select(func.count(EasmAsset.id)).where(q.whereclause)) or 0

    async def fetch_page():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            page_q = q.order_by(EasmAsset.hostname).offset((page - 1) * per_page).limit(per_page)
            res = await db.execute(page_q)
            return res.scalars().all()

    total, assets = await asyncio.gather(fetch_total(), fetch_page())

    from collections import defaultdict
    from app.models.finding import Finding
    findings_map = defaultdict(list)
    if assets:
        hostnames = [a.hostname for a in assets]
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            findings_q = select(Finding.entity, Finding.issue_type, Finding.severity, Finding.evidence).where(
                and_(
                    Finding.tenant_id == current_user.tenant_id,
                    Finding.status == "open",
                    Finding.entity.in_(hostnames)
                )
            )
            findings_res = await db.execute(findings_q)
            for entity, issue_type, severity, evidence in findings_res.all():
                findings_map[entity].append({"issue_type": issue_type, "severity": severity, "evidence": evidence})

    def _subdomain_to_dict(a: EasmAsset, findings: list = None) -> dict:
        import json
        parsed_stack = []
        for item in (a.tech_stack or []):
            try:
                obj = json.loads(item)
                if obj.get("version"):
                    parsed_stack.append(f"{obj['name']} {obj['version']}")
                else:
                    parsed_stack.append(obj["name"])
            except json.JSONDecodeError:
                parsed_stack.append(item)
                
        return {
            "id": str(a.id),
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "http_status": a.http_status,
            "status": a.status,
            "is_catch_all": a.is_catch_all,
            "is_exposed_admin": a.is_exposed_admin,
            "tech_stack": parsed_stack,
            "sec_headers_grade": a.sec_headers_grade,
            "cve_count": a.cve_count,
            "discovered_at": a.discovered_at.isoformat() if a.discovered_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "issues": findings or [],
        }

    return {
        "subdomains": [_subdomain_to_dict(a, findings_map.get(a.hostname, [])) for a in assets],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
    }


@router.post("/rescan")
async def trigger_rescan(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Manually trigger a full EASM rescan for the tenant.
    Reads current scan_scopes and re-probes all domains.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    scopes_result = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.tenant_id == current_user.tenant_id,
                ScanScope.type == "domain",
            )
        )
    )
    scopes = scopes_result.scalars().all()

    if not scopes:
        raise HTTPException(status_code=400, detail="No domain scopes defined. Add domains in Settings first.")

    scope_values = [s.value for s in scopes]
    background_tasks.add_task(run_easm_scan, str(current_user.tenant_id), scope_values)

    return {
        "message": f"EASM rescan started for {len(scope_values)} domain(s).",
        "targets": scope_values,
    }


@router.post("/cancel-scan")
async def cancel_scan(
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Cancel the currently running EASM scan job.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    # Find active scan job
    result = await session.execute(
        select(ScanJob)
        .where(
            and_(
                ScanJob.tenant_id == current_user.tenant_id,
                ScanJob.job_type == "easm",
                ScanJob.status.in_(["queued", "running"])
            )
        )
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=400, detail="No active scan job found to cancel.")

    from datetime import datetime, timezone
    job.status = "failed"
    job.error_message = "Cancelled by user"
    job.completed_at = datetime.now(timezone.utc)
    await session.commit()

    return {"message": "Scan cancelled successfully."}


@router.get("/scan-status")
async def get_scan_status(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """
    Returns the most recent EASM scan job for the tenant.
    Frontend polls this to show live scan progress.
    """
    try:
        await set_rls_tenant(session, str(current_user.tenant_id))

        result = await session.execute(
            select(ScanJob)
            .where(
                and_(
                    ScanJob.tenant_id == current_user.tenant_id,
                    ScanJob.job_type == "easm",
                )
            )
            .order_by(ScanJob.created_at.desc())
            .limit(1)
        )
        job = result.scalar_one_or_none()

        if not job:
            return {"has_job": False, "status": None, "progress": None}
    except Exception as e:
        # If DB connection drops due to local DNS/Network exhaustion during aggressive scan,
        # return a graceful running state so the frontend doesn't crash or stop polling.
        return {
            "has_job": True, 
            "status": "running", 
            "percent_complete": 0,
            "elapsed_seconds": 0,
            "targets": ["Connecting to Database..."]
        }

    meta = job.metadata_ or {}
    total = meta.get("total", 0)
    completed = meta.get("completed", 0)
    failed = meta.get("failed", 0)
    modules = meta.get("modules")
    
    phase = meta.get("phase", "discovery")
    vuln_total = meta.get("vuln_total", 0)
    vuln_completed = meta.get("vuln_completed", 0)
    vuln_failed = meta.get("vuln_failed", 0)

    # Determine if vuln scanning is active/requested
    has_vuln = not modules or "vuln" in modules
    
    if not has_vuln:
        percent = round((completed + failed) / total * 100) if total > 0 else 0
    else:
        # Phase 1: asset discovery maps to 0-50%
        # Phase 2: nuclei vulnerability maps to 50-100%
        if phase == "discovery" or phase != "vuln":
            disc_percent = (completed + failed) / total if total > 0 else 0
            percent = round(disc_percent * 50)
        else:
            # We are in vuln phase
            vuln_percent = (vuln_completed + vuln_failed) / vuln_total if vuln_total > 0 else 0
            percent = round(50 + (vuln_percent * 50))

    from datetime import datetime, timezone
    
    elapsed_seconds = 0
    if job.started_at:
        end_time = job.completed_at if job.completed_at else datetime.now(timezone.utc)
        elapsed_seconds = max(0, int((end_time - job.started_at).total_seconds()))

    return {
        "has_job": True,
        "job_id": str(job.id),
        "status": job.status,          # queued | running | completed | failed
        "targets": meta.get("targets", []),
        
        # Keep old properties for backward compatibility
        "total": total if phase != "vuln" else vuln_total,
        "completed": completed if phase != "vuln" else vuln_completed,
        "failed": failed if phase != "vuln" else vuln_failed,
        
        "percent_complete": percent,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "elapsed_seconds": elapsed_seconds,
        "error_message": job.error_message,
        
        # New multi-phase properties
        "phase": phase,
        "vuln_total": vuln_total,
        "vuln_completed": vuln_completed,
        "vuln_failed": vuln_failed,
    }




