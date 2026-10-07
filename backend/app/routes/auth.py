"""
Authentication & User Identity Routes
Handles user registration, login, token refresh, and identity introspection.
"""
from flask import Blueprint, jsonify, request, g
from ..models.database import db, User, Organization, Membership, SecurityPolicy
from ..security.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    require_auth,
    get_tenant_org_id,
)
from ..security.audit import log_audit_event
from datetime import datetime, timezone
import re

auth_bp = Blueprint('auth', __name__)


def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(pattern, email.strip()))


@auth_bp.route('/v1/auth/register', methods=['POST'])
def register():
    """Register a new user and create their default workspace organization."""
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    full_name = (data.get('full_name') or '').strip()
    org_name = (data.get('org_name') or '').strip() or f"{full_name or email.split('@')[0]}'s Workspace"

    if not email or not is_valid_email(email):
        return jsonify({"status": "error", "message": "Valid email address is required"}), 400
    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters long"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"status": "error", "message": "Email is already registered"}), 409

    # 1. Create User
    user = User(
        email=email,
        full_name=full_name,
        is_active=True,
        created_at=datetime.now(timezone.utc)
    )
    user.set_password(password)
    db.session.add(user)
    db.session.flush()

    # 2. Create Organization
    slug = re.sub(r'[^a-z0-9-]', '-', org_name.lower().replace(' ', '-')).strip('-')
    slug = f"{slug}-{user.id}"
    org = Organization(
        name=org_name,
        slug=slug,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(org)
    db.session.flush()

    # 3. Add User as Owner
    membership = Membership(
        user_id=user.id,
        organization_id=org.id,
        role="Owner",
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(membership)

    # 4. Default Organization Security Policy
    policy = SecurityPolicy(
        organization_id=org.id,
        project_id=None,
        name="Organization Baseline Gate Policy",
        block_critical=True,
        block_high=True,
        block_medium=False,
        min_cvss_block=7.0,
        max_critical_allowed=0,
        max_high_allowed=0,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(policy)

    db.session.commit()

    # Audit log
    log_audit_event(
        organization_id=org.id,
        user_id=user.id,
        user_email=user.email,
        action="user.register",
        resource_type="User",
        resource_id=str(user.id),
        details={"email": user.email, "org": org.name}
    )

    access_token = create_access_token(user.id, user.email, org.id, "Owner")
    refresh_token = create_refresh_token(user.id)

    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict(),
        "organization": org.to_dict(),
        "role": "Owner"
    }), 201


@auth_bp.route('/v1/auth/login', methods=['POST'])
def login():
    """Authenticate with email and password and return signed JWT."""
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        # Record failed login audit if user was found
        if user and user.memberships:
            log_audit_event(
                organization_id=user.memberships[0].organization_id,
                user_id=user.id,
                user_email=email,
                action="user.login_failed",
                resource_type="User",
                resource_id=str(user.id),
                details={"reason": "Invalid credentials"}
            )
        return jsonify({"status": "error", "message": "Invalid email or password"}), 401

    if not user.is_active:
        return jsonify({"status": "error", "message": "Account has been deactivated"}), 403

    # Primary organization & role
    membership = user.memberships[0] if user.memberships else None
    org_id = membership.organization_id if membership else 1
    role = membership.role if membership else "Developer"

    access_token = create_access_token(user.id, user.email, org_id, role)
    refresh_token = create_refresh_token(user.id)

    log_audit_event(
        organization_id=org_id,
        user_id=user.id,
        user_email=user.email,
        action="user.login",
        resource_type="User",
        resource_id=str(user.id),
        details={"role": role}
    )

    return jsonify({
        "status": "success",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict(),
        "organization": membership.organization.to_dict() if membership else None,
        "role": role
    }), 200


@auth_bp.route('/v1/auth/refresh', methods=['POST'])
def refresh():
    """Exchange valid refresh token for a new access token."""
    data = request.get_json() or {}
    token = data.get('refresh_token')
    if not token:
        return jsonify({"status": "error", "message": "refresh_token is required"}), 400

    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            return jsonify({"status": "error", "message": "Invalid token type"}), 400

        user_id = int(payload.get("user_id", payload.get("sub")))
        user = db.session.get(User, user_id)
        if not user or not user.is_active:
            return jsonify({"status": "error", "message": "User account inactive or not found"}), 401

        membership = user.memberships[0] if user.memberships else None
        org_id = membership.organization_id if membership else 1
        role = membership.role if membership else "Developer"

        new_access_token = create_access_token(user.id, user.email, org_id, role)
        return jsonify({
            "status": "success",
            "access_token": new_access_token
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Token refresh failed: {str(e)}"}), 401


@auth_bp.route('/v1/auth/me', methods=['GET'])
@require_auth
def get_me():
    """Introspect current authenticated user identity and organization memberships."""
    user_payload = g.current_user
    user = db.session.get(User, user_payload["user_id"])
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    memberships = [
        {
            "organization": m.organization.to_dict(),
            "role": m.role
        }
        for m in user.memberships
    ]

    return jsonify({
        "status": "success",
        "user": user.to_dict(),
        "memberships": memberships,
        "current_org_id": user_payload.get("org_id"),
        "current_role": user_payload.get("role")
    }), 200
