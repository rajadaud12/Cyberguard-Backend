"""
CyberGuard — Onboarding Router
Endpoints: add scan scopes, verify domain ownership, check onboarding status.
"""
import asyncio
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.dependencies import get_db, get_current_user, get_client_ip, require_admin
from app.database import set_rls_tenant
from app.models.user import User
from app.models.tenant import Tenant
from app.models.scope import ScanScope
from app.models.m365_credential import M365Credential
from app.schemas.onboarding import (
    AddScopeRequest, AddScopeResponse, ScopeItemResponse,
    VerifyScopeResponse, OnboardingStatusResponse,
)
from app.services.dns_service import (
    generate_verification_token,
    validate_domain_format,
    validate_cidr_format,
    check_dns_txt_verification,
)
from app.services.audit_service import log_action, AuditAction

router = APIRouter(prefix="/api/v1/onboarding", tags=["Onboarding"])


def _scope_to_response(scope: ScanScope) -> ScopeItemResponse:
    return ScopeItemResponse(
        id=str(scope.id),
        type=scope.type,
        value=scope.value,
        verified=scope.verified,
        verification_token=scope.verification_token if scope.type == "domain" else None,
        verified_at=scope.verified_at.isoformat() if scope.verified_at else None,
    )


@router.post("/scope", response_model=AddScopeResponse, status_code=201)
async def add_scope(
    payload: AddScopeRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Add root domains and CIDR ranges to the tenant's authorized scan scope.
    Domains get a DNS TXT verification token; CIDRs are immediately saved.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    created_scopes = []
    
    for item in payload.scopes:
        # Validate format
        if item.type == "domain":
            valid, error = validate_domain_format(item.value)
        else:
            valid, error = validate_cidr_format(item.value)
        
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=error,
            )
        
        # Check if already exists for this tenant
        existing = await session.execute(
            select(ScanScope).where(
                and_(
                    ScanScope.tenant_id == current_user.tenant_id,
                    ScanScope.value == item.value,
                )
            )
        )
        if existing.scalar_one_or_none():
            # Skip duplicates silently
            continue
        
        # Generate verification token for domains
        is_subdomain_of_verified = False
        if item.type == "domain":
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
                if item.value.endswith("." + p.value):
                    is_subdomain_of_verified = True
                    break

        verification_token = None
        is_verified = (item.type == "cidr") or is_subdomain_of_verified
        
        if item.type == "domain" and not is_verified:
            verification_token = generate_verification_token()
        
        scope = ScanScope(
            tenant_id=current_user.tenant_id,
            type=item.type,
            value=item.value,
            verified=is_verified,
            verification_token=verification_token,
            verified_at=datetime.now(timezone.utc) if is_verified else None
        )
        session.add(scope)
        await session.flush()
        created_scopes.append(scope)
        
        await log_action(
            session=session,
            tenant_id=current_user.tenant_id,
            actor_user_id=current_user.id,
            action=AuditAction.SCOPE_ADDED,
            ip_address=get_client_ip(request),
            metadata={"type": item.type, "value": item.value},
        )
    
    return AddScopeResponse(
        scopes=[_scope_to_response(s) for s in created_scopes],
        message=f"{len(created_scopes)} scope(s) added. Domains require DNS verification.",
    )


@router.get("/scope", response_model=List[ScopeItemResponse])
async def list_scopes(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """List all scan scopes for the current tenant."""
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    result = await session.execute(
        select(ScanScope).where(ScanScope.tenant_id == current_user.tenant_id)
    )
    scopes = result.scalars().all()
    return [_scope_to_response(s) for s in scopes]


@router.post("/scope/{scope_id}/verify", response_model=VerifyScopeResponse)
async def verify_scope(
    scope_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Trigger a live DNS TXT record lookup to verify domain ownership.
    Must be called after the admin has added the TXT record to their DNS zone.
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
        raise HTTPException(status_code=404, detail="Scope not found or not a domain type.")
    
    if scope.verified:
        return VerifyScopeResponse(
            scope_id=str(scope.id),
            domain=scope.value,
            verified=True,
            message="Domain is already verified.",
            attempts=scope.verification_attempts,
        )
    
    # Increment attempt counter
    scope.verification_attempts += 1
    
    await log_action(
        session=session,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=AuditAction.SCOPE_VERIFY_ATTEMPTED,
        ip_address=get_client_ip(request),
        metadata={"domain": scope.value, "attempt": scope.verification_attempts},
    )
    
    # Run DNS check in thread pool (dnspython is synchronous)
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
        
        await log_action(
            session=session,
            tenant_id=current_user.tenant_id,
            actor_user_id=current_user.id,
            action=AuditAction.SCOPE_VERIFIED,
            metadata={"domain": scope.value},
        )
    else:
        await log_action(
            session=session,
            tenant_id=current_user.tenant_id,
            actor_user_id=current_user.id,
            action=AuditAction.SCOPE_VERIFY_FAILED,
            metadata={"domain": scope.value, "reason": message},
        )
    
    return VerifyScopeResponse(
        scope_id=str(scope.id),
        domain=scope.value,
        verified=verified,
        message=message,
        attempts=scope.verification_attempts,
    )


@router.post("/scope/{scope_id}/skip", response_model=VerifyScopeResponse)
async def skip_verify_scope(
    scope_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Skip DNS TXT record verification for testing.
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
        raise HTTPException(status_code=404, detail="Scope not found or not a domain type.")
    
    scope.verified = True
    scope.verified_at = datetime.now(timezone.utc)
    
    await log_action(
        session=session,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=AuditAction.SCOPE_VERIFIED,
        metadata={"domain": scope.value, "note": "Skipped for testing"},
    )
    
    return VerifyScopeResponse(
        scope_id=str(scope.id),
        domain=scope.value,
        verified=True,
        message="Domain verification skipped for testing.",
        attempts=scope.verification_attempts,
    )


@router.get("/status", response_model=OnboardingStatusResponse)
async def get_onboarding_status(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """
    Returns the full onboarding checklist state for the current tenant.
    Used by the frontend wizard to determine which steps are complete.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    # Fetch tenant
    tenant = await session.get(Tenant, current_user.tenant_id)
    
    # Fetch scopes
    scopes_result = await session.execute(
        select(ScanScope).where(ScanScope.tenant_id == current_user.tenant_id)
    )
    scopes = scopes_result.scalars().all()
    
    # Check M365
    m365_result = await session.execute(
        select(M365Credential).where(
            and_(
                M365Credential.tenant_id == current_user.tenant_id,
                M365Credential.token_status == "active",
            )
        )
    )
    m365 = m365_result.scalar_one_or_none()
    
    domain_scopes = [s for s in scopes if s.type == "domain"]
    has_verified_domain = any(s.verified for s in domain_scopes)
    
    checklist = {
        "scopes_added": len(scopes) > 0,
        "domain_verified": has_verified_domain,
        "m365_connected": m365 is not None,
        "baseline_scan_queued": tenant.onboarding_step >= 4,
    }
    
    return OnboardingStatusResponse(
        tenant_id=str(tenant.id),
        onboarding_step=tenant.onboarding_step,
        status=tenant.status,
        scopes=[_scope_to_response(s) for s in scopes],
        m365_connected=m365 is not None,
        checklist=checklist,
    )
