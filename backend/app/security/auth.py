"""
SecureGate Enterprise Authentication & RBAC Service
Implements bcrypt password hashing, JWT tokens with role-based access control,
and multi-tenant organization context management.
"""
import os
import datetime
from functools import wraps
from typing import Optional, Dict, Any, List

import bcrypt
import jwt
from flask import request, jsonify, g

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", os.environ.get("SECRET_KEY", "securegate-enterprise-jwt-secret-key-2026"))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# RBAC Hierarchy
ROLE_HIERARCHY = {
    "Owner": 5,
    "Admin": 4,
    "Security Engineer": 3,
    "Developer": 2,
    "Viewer": 1,
}


def hash_password(password: str) -> str:
    """Hash plaintext password using bcrypt with salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plaintext password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: int, email: str, org_id: Optional[int] = None, role: Optional[str] = None) -> str:
    """Generate signed JWT access token."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user_id),
        "user_id": user_id,
        "email": email,
        "org_id": org_id,
        "role": role or "Developer",
        "type": "access",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    """Generate signed JWT refresh token."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user_id),
        "user_id": user_id,
        "type": "refresh",
        "iat": now,
        "exp": now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")


def get_current_user_from_request() -> Optional[Dict[str, Any]]:
    """Extract authenticated user payload from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            return None
        return payload
    except Exception:
        return None


def require_auth(f):
    """Decorator requiring a valid JWT access token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user_from_request()
        if not user:
            return jsonify({
                "status": "error",
                "message": "Authentication required. Provide a valid Bearer token."
            }), 401

        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function


def require_role(*allowed_roles: str):
    """Decorator requiring one of the specified RBAC roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, "current_user", None) or get_current_user_from_request()
            if not user:
                return jsonify({"status": "error", "message": "Authentication required"}), 401

            g.current_user = user
            user_role = user.get("role", "Viewer")

            # Check if user has sufficient role level
            if user_role not in allowed_roles:
                min_required = min([ROLE_HIERARCHY.get(r, 99) for r in allowed_roles])
                user_level = ROLE_HIERARCHY.get(user_role, 0)
                if user_level < min_required:
                    return jsonify({
                        "status": "error",
                        "message": f"Forbidden: Action requires one of roles: {', '.join(allowed_roles)}. Current role: {user_role}"
                    }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_tenant_org_id() -> int:
    """
    Extract tenant organization ID from request header (X-Organization-ID),
    JWT claims, or query param. Fallback to default Org 1.
    """
    header_org = request.headers.get("X-Organization-ID")
    if header_org and header_org.isdigit():
        return int(header_org)

    user = getattr(g, "current_user", None)
    if user and user.get("org_id"):
        return int(user["org_id"])

    arg_org = request.args.get("org_id", type=int)
    if arg_org:
        return arg_org

    return 1


get_authenticated_user_context = get_current_user_from_request
