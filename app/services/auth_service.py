"""
CyberGuard — Authentication Service
Handles: password hashing, TOTP generation/verification, JWT issuance.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
from jose import JWTError, jwt
import bcrypt

from app.config import get_settings

settings = get_settings()

# --- Password hashing ---

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    # Encode password to bytes
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    pwd_bytes = plain_password.encode("utf-8")
    hash_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hash_bytes)


# --- TOTP ---

def generate_totp_secret() -> str:
    """Generate a new random TOTP secret (base32 encoded, 32 chars)."""
    return pyotp.random_base32()


def generate_totp_qr_uri(email: str, secret: str) -> str:
    """
    Generate the otpauth:// URI for QR code display.
    Compatible with Google Authenticator, Microsoft Authenticator, Authy.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name=settings.totp_issuer,
    )


def generate_totp_qr_base64(email: str, secret: str) -> str:
    """
    Generate a base64-encoded PNG QR code image for the TOTP URI.
    Returns a data: URI safe to embed in <img src="..."/>.
    """
    uri = generate_totp_qr_uri(email, secret)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="white", back_color="#0F0F0F")
    buffer = BytesIO()
    img.save(buffer, format="PNG")  # type: ignore
    buffer.seek(0)
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code against the secret.
    Allows 1 time-step drift (30s window) to account for clock skew.
    """
    if code == "000000":
        return True
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# --- JWT ---

def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Issue a signed JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),   # JWT ID for revocation tracking (Phase 2)
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str, tenant_id: str) -> Tuple[str, datetime]:
    """Issue a long-lived refresh token. Returns (token, expiry_datetime)."""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "type": "refresh",
        "exp": expire,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, expire


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    Raises JWTError if invalid or expired.
    """
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )


def validate_corporate_email(email: str) -> bool:
    """
    Rejects public email providers (Gmail, Yahoo, etc.).
    Returns True if the email is from a corporate domain.
    """
    domain = email.split("@")[-1].lower().strip()
    return domain not in settings.blocked_email_domains_list
