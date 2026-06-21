"""
CyberGuard — EASM SQLAlchemy Models
EasmAsset, EasmPort, EasmCertificate
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text,
    ForeignKey, ARRAY, Enum as PgEnum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class EasmAsset(Base):
    __tablename__ = "easm_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(512), nullable=False)
    ip_address = Column(String(64), nullable=True)  # stored as text to avoid INET casting issues
    http_status = Column(Integer, nullable=True)
    asset_type = Column(String(50), default="web")
    tech_stack = Column(ARRAY(Text), nullable=False, default=list)
    sec_headers_grade = Column(
        PgEnum("A", "B", "C", "D", "F", "unknown", name="sec_headers_grade"),
        nullable=False, default="unknown"
    )
    cve_count = Column(Integer, nullable=False, default=0)
    is_catch_all = Column(Boolean, nullable=False, default=False)
    is_exposed_admin = Column(Boolean, nullable=False, default=False)
    status = Column(
        PgEnum("active", "inactive", "unknown", name="asset_status"),
        nullable=False, default="active"
    )
    asset_criticality = Column(
        PgEnum("critical", "high", "medium", "low", "unknown", name="asset_criticality"),
        nullable=False, default="unknown"
    )
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    discovered_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    ports = relationship("EasmPort", back_populates="asset", cascade="all, delete-orphan")


class EasmPort(Base):
    __tablename__ = "easm_ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("easm_assets.id", ondelete="CASCADE"), nullable=True)
    ip_address = Column(String(64), nullable=False)  # stored as text to avoid INET casting issues
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, default="tcp")
    service = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)
    provider = Column(String(256), nullable=True)
    location = Column(String(10), nullable=True)
    risk_level = Column(
        PgEnum("critical", "high", "medium", "low", "info", name="risk_level"),
        nullable=False, default="info"
    )
    is_risky = Column(Boolean, nullable=False, default=False)
    discovered_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    asset = relationship("EasmAsset", back_populates="ports")


class EasmCertificate(Base):
    __tablename__ = "easm_certificates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(512), nullable=False)
    issuer = Column(String(512), nullable=True)
    subject = Column(String(512), nullable=True)
    serial_number = Column(String(256), nullable=True)
    fingerprint = Column(String(128), nullable=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_to = Column(DateTime(timezone=True), nullable=True)
    is_expired = Column(Boolean, nullable=False, default=False)
    is_self_signed = Column(Boolean, nullable=False, default=False)
    is_mismatch = Column(Boolean, nullable=False, default=False)
    days_to_expiry = Column(Integer, nullable=True)
    sans = Column(ARRAY(Text), nullable=False, default=list)
    discovered_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
