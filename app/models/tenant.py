"""Tenant ORM Model"""
import uuid
from datetime import datetime
from typing import TYPE_CHECKING
from sqlalchemy import String, DateTime, Integer, func
from sqlalchemy.dialects.postgresql import UUID, ENUM
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.scan_scope import ScanScope
    from app.models.m365_credential import M365Credential
    from app.models.audit_trail import AuditTrail
    from app.models.scan_job import ScanJob



class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        ENUM("onboarding", "active", "suspended", name="tenant_status", create_type=False),
        nullable=False, default="onboarding"
    )
    onboarding_step: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="tenant")
    scan_scopes: Mapped[list["ScanScope"]] = relationship("ScanScope", back_populates="tenant")
    m365_credential: Mapped["M365Credential"] = relationship(
        "M365Credential", back_populates="tenant", uselist=False
    )
    audit_trail: Mapped[list["AuditTrail"]] = relationship("AuditTrail", back_populates="tenant")
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="tenant")

    def __repr__(self) -> str:
        return f"<Tenant id={self.id} org={self.org_name} status={self.status}>"
