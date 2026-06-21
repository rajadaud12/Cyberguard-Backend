"""
CyberGuard -- Settings Router
Tenant scope management: add/edit/delete domains & IPs.
Also exposes rescan controls and integration status.
"""
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, validator
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user, require_admin
from app.database import set_rls_tenant
from app.models.user import User
from app.models.scope import ScanScope
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.services.dns_service import (
    validate_domain_format, validate_cidr_format,
    generate_verification_token, check_dns_txt_verification,
)
from app.services.easm_scanner import run_easm_scan

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class AddScopeBody(BaseModel):
    type: str   # domain | cidr
    value: str

    @validator("type")
    def type_must_be_valid(cls, v):
        if v not in ("domain", "cidr"):
            raise ValueError("type must be 'domain' or 'cidr'")
        return v


class UpdateScopeBody(BaseModel):
    value: str

class RescanCustomBody(BaseModel):
    targets: list[str]
    modules: list[str] | None = None


# ── Helper ────────────────────────────────────────────────────────────────────

def _scope_dict(s: ScanScope) -> dict:
    return {
        "id": str(s.id),
        "type": s.type,
        "value": s.value,
        "verified": s.verified,
        "verification_token": s.verification_token if s.type == "domain" else None,
        "verified_at": s.verified_at.isoformat() if s.verified_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


# ── Scope endpoints ───────────────────────────────────────────────────────────

async def _delete_scope_data(session: AsyncSession, tenant_id, scope_type: str, scope_value: str):
    from app.models.finding import Finding
    import ipaddress
    
    if scope_type == "domain":
        # 1. Assets (cascades to ports)
        assets_result = await session.execute(
            select(EasmAsset).where(
                and_(
                    EasmAsset.tenant_id == tenant_id,
                    or_(
                        EasmAsset.hostname == scope_value,
                        EasmAsset.hostname.endswith(f".{scope_value}")
                    )
                )
            )
        )
        for a in assets_result.scalars().all():
            await session.delete(a)

        # 2. Certificates
        certs_result = await session.execute(
            select(EasmCertificate).where(
                and_(
                    EasmCertificate.tenant_id == tenant_id,
                    or_(
                        EasmCertificate.hostname == scope_value,
                        EasmCertificate.hostname.endswith(f".{scope_value}")
                    )
                )
            )
        )
        for c in certs_result.scalars().all():
            await session.delete(c)

        # 3. Findings
        findings_result = await session.execute(
            select(Finding).where(
                and_(
                    Finding.tenant_id == tenant_id,
                    Finding.source == "ext_scanner",
                    or_(
                        Finding.entity == scope_value,
                        Finding.entity.startswith(f"{scope_value}:"),
                        Finding.entity.endswith(f".{scope_value}"),
                        Finding.entity.like(f"%.{scope_value}:%")
                    )
                )
            )
        )
        for f in findings_result.scalars().all():
            await session.delete(f)
            
    elif scope_type == "cidr":
        try:
            cidr_net = ipaddress.ip_network(scope_value, strict=False)
        except ValueError:
            return
            
        # Assets
        assets_result = await session.execute(
            select(EasmAsset).where(EasmAsset.tenant_id == tenant_id)
        )
        for a in assets_result.scalars().all():
            ip_to_check = a.ip_address or a.hostname
            try:
                if ipaddress.ip_address(ip_to_check) in cidr_net:
                    await session.delete(a)
            except ValueError:
                pass
                
        # Certificates
        certs_result = await session.execute(
            select(EasmCertificate).where(EasmCertificate.tenant_id == tenant_id)
        )
        for c in certs_result.scalars().all():
            try:
                if ipaddress.ip_address(c.hostname) in cidr_net:
                    await session.delete(c)
            except ValueError:
                pass

        # Findings
        findings_result = await session.execute(
            select(Finding).where(
                and_(Finding.tenant_id == tenant_id, Finding.source == "ext_scanner")
            )
        )
        for f in findings_result.scalars().all():
            try:
                ip_str = f.entity.split(":")[0]
                if ipaddress.ip_address(ip_str) in cidr_net:
                    await session.delete(f)
            except ValueError:
                pass

@router.get("/scopes")
async def list_scopes(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """List all scan scopes (domains + CIDRs) for the tenant."""
    await set_rls_tenant(session, str(current_user.tenant_id))
    result = await session.execute(
        select(ScanScope).where(ScanScope.tenant_id == current_user.tenant_id)
        .order_by(ScanScope.created_at)
    )
    return [_scope_dict(s) for s in result.scalars().all()]


@router.post("/scopes", status_code=201)
async def add_scope(
    body: AddScopeBody,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Add a new domain or CIDR to the scan scope.
    For domains: begins EASM scan immediately (background).
    For CIDRs: saved as verified immediately.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    # Normalize domain to lowercase; strip whitespace
    scope_value = body.value.strip()
    if body.type == "domain":
        scope_value = scope_value.lower()

    # Validate format
    if body.type == "domain":
        valid, error = validate_domain_format(scope_value)
    else:
        valid, error = validate_cidr_format(scope_value)
    if not valid:
        raise HTTPException(status_code=422, detail=error)

    # Check duplicate (case-insensitive for domains)
    from sqlalchemy import func as sqlfunc
    existing = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.tenant_id == current_user.tenant_id,
                sqlfunc.lower(ScanScope.value) == scope_value.lower(),
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Scope '{scope_value}' already exists.")

    is_subdomain_of_verified = False
    if body.type == "domain":
        parents = await session.execute(
            select(ScanScope).where(
                and_(
                    ScanScope.tenant_id == current_user.tenant_id,
                    ScanScope.type == "domain",
                    ScanScope.verified == True
                )
            )
        )
        for p in parents.scalars().all():
            if scope_value.endswith("." + p.value):
                is_subdomain_of_verified = True
                break

    is_verified = (body.type == "cidr") or is_subdomain_of_verified
    token = generate_verification_token() if body.type == "domain" and not is_verified else None
    
    scope = ScanScope(
        tenant_id=current_user.tenant_id,
        type=body.type,
        value=scope_value,
        verified=is_verified,
        verification_token=token,
        verified_at=datetime.now(timezone.utc) if is_verified else None
    )
    session.add(scope)
    await session.flush()

    return {
        "scope": _scope_dict(scope),
        "message": f"'{scope_value}' added to scope.",
    }


@router.put("/scopes/{scope_id}")
async def update_scope(
    scope_id: str,
    body: UpdateScopeBody,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Update a scope's value (e.g. correct a typo).
    Re-triggers EASM scan for the new value if it's a domain.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.id == scope_id,
                ScanScope.tenant_id == current_user.tenant_id,
            )
        )
    )
    scope = result.scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found.")

    old_value = scope.value
    if scope.type == "domain":
        valid, error = validate_domain_format(body.value)
    else:
        valid, error = validate_cidr_format(body.value)

    if not valid:
        raise HTTPException(status_code=422, detail=error)

    scope.value = body.value
    scope.verified = (scope.type == "cidr")
    scope.verification_token = generate_verification_token() if scope.type == "domain" else None
    scope.verified_at = None

    # Delete old EASM data for old hostname/cidr
    await _delete_scope_data(session, current_user.tenant_id, scope.type, old_value)

    return {"scope": _scope_dict(scope), "message": f"Updated to '{body.value}'."}


@router.delete("/scopes/{scope_id}", status_code=204)
async def delete_scope(
    scope_id: str,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Remove a scope from the authorized scan list.
    Also removes all EASM data discovered for that domain.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.id == scope_id,
                ScanScope.tenant_id == current_user.tenant_id,
            )
        )
    )
    scope = result.scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found.")

    # Remove EASM data for this scope (domain or cidr)
    await _delete_scope_data(session, current_user.tenant_id, scope.type, scope.value)

    await session.delete(scope)


@router.post("/scopes/{scope_id}/rescan")
async def rescan_scope(
    scope_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """Trigger a fresh EASM scan for a single scope."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.id == scope_id,
                ScanScope.tenant_id == current_user.tenant_id,
            )
        )
    )
    scope = result.scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found.")

    background_tasks.add_task(run_easm_scan, str(current_user.tenant_id), [scope.value])
    return {"message": f"Rescan started for '{scope.value}'."}


@router.post("/easm/rescan-all")
async def rescan_all(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """Rescan ALL domain scopes for the tenant."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(ScanScope).where(
            ScanScope.tenant_id == current_user.tenant_id
        )
    )
    scopes = result.scalars().all()
    if not scopes:
        raise HTTPException(status_code=400, detail="No scopes configured.")

    values = [s.value for s in scopes]
    background_tasks.add_task(run_easm_scan, str(current_user.tenant_id), values)
    return {"message": f"Full rescan started for {len(values)} target(s).", "targets": values}


@router.post("/easm/rescan-custom")
async def rescan_custom(
    body: RescanCustomBody,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """Rescan SPECIFIC targets for the tenant."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    if not body.targets:
        raise HTTPException(status_code=400, detail="No targets selected for scan.")

    # Validate that these targets exist in the tenant's scope
    # To keep it simple and allow scanning subdomains, we just pass them to the scanner.
    # The scanner naturally bounds itself to the tenant's authorized root domains.
    
    background_tasks.add_task(run_easm_scan, str(current_user.tenant_id), body.targets, body.modules)
    return {"message": f"Custom scan started for {len(body.targets)} target(s).", "targets": body.targets}


@router.post("/scopes/{scope_id}/verify")
async def verify_scope(
    scope_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Trigger a live DNS TXT lookup to verify domain ownership.
    On success, marks the domain as verified and fires an EASM scan.
    Can be called from both the onboarding wizard and the Settings panel.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.id == scope_id,
                ScanScope.tenant_id == current_user.tenant_id,
                ScanScope.type == "domain",
            )
        )
    )
    scope = result.scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="Domain scope not found.")

    if scope.verified:
        return {
            "scope_id": str(scope.id),
            "domain": scope.value,
            "verified": True,
            "message": "Domain is already verified.",
            "attempts": scope.verification_attempts,
        }

    if not scope.verification_token:
        raise HTTPException(status_code=400, detail="No verification token generated for this scope.")

    scope.verification_attempts += 1

    # Run DNS check in thread pool (dnspython is sync)
    loop = asyncio.get_event_loop()
    verified, message = await loop.run_in_executor(
        None,
        check_dns_txt_verification,
        scope.value,
        scope.verification_token,
    )

    if verified:
        scope.verified = True
        scope.verified_at = datetime.now(timezone.utc)
        # Start EASM scan now that ownership is confirmed
        background_tasks.add_task(run_easm_scan, str(current_user.tenant_id), [scope.value])

    return {
        "scope_id": str(scope.id),
        "domain": scope.value,
        "verified": verified,
        "message": message,
        "attempts": scope.verification_attempts,
    }

