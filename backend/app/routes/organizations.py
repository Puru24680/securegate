"""
Organizations & Workspace Management routes
Supports multi-tenancy, team membership, RBAC role assignment, and organization metrics.
"""
import re
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from ..models.database import db, Organization, Membership, User, Project, SecurityPolicy
from ..security.auth import (
    require_auth, require_role, get_authenticated_user_context, get_tenant_org_id
)
from ..security.audit import AuditLogger

orgs_bp = Blueprint('organizations', __name__)


@orgs_bp.route('/organizations', methods=['GET'])
@orgs_bp.route('/v1/organizations', methods=['GET'])
def list_organizations():
    """List organizations accessible by the user."""
    user_ctx = get_authenticated_user_context()
    if user_ctx:
        user_id = user_ctx['user_id']
        memberships = Membership.query.filter_by(user_id=user_id).all()
        org_ids = [m.organization_id for m in memberships]
        orgs = Organization.query.filter(Organization.id.in_(org_ids)).all()
    else:
        orgs = Organization.query.all()

    return jsonify({
        "status": "success",
        "organizations": [o.to_dict() for o in orgs]
    }), 200


@orgs_bp.route('/organizations', methods=['POST'])
@orgs_bp.route('/v1/organizations', methods=['POST'])
def create_organization():
    """Create a new organization workspace."""
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({"status": "error", "message": "Organization name is required"}), 400

    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    existing = Organization.query.filter_by(slug=slug).first()
    if existing:
        slug = f"{slug}-{int(datetime.now(timezone.utc).timestamp())}"

    org = Organization(
        name=name,
        slug=slug,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(org)
    db.session.flush()

    user_ctx = get_authenticated_user_context()
    user_id = user_ctx['user_id'] if user_ctx else 1
    membership = Membership(
        user_id=user_id,
        organization_id=org.id,
        role="Owner",
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(membership)

    # Initialize default security policy
    default_policy = SecurityPolicy(
        organization_id=org.id,
        project_id=None,
        name=f"{name} Baseline Policy",
        block_critical=True,
        block_high=True,
        block_medium=False,
        min_cvss_block=7.0,
        max_critical_allowed=0,
        max_high_allowed=0,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(default_policy)
    db.session.commit()

    AuditLogger.log(
        org_id=org.id,
        action="organization.created",
        resource_type="organization",
        resource_id=str(org.id),
        user_id=user_id,
        user_email=user_ctx.get("email") if user_ctx else "system",
        details={"name": name, "slug": slug}
    )

    return jsonify({
        "status": "success",
        "message": f"Organization '{name}' created successfully",
        "organization": org.to_dict()
    }), 201


@orgs_bp.route('/organizations/<int:org_id>', methods=['GET'])
@orgs_bp.route('/v1/organizations/<int:org_id>', methods=['GET'])
def get_organization(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    data = org.to_dict()
    data['members'] = [m.to_dict() for m in org.memberships]
    data['projects'] = [p.to_dict() for p in org.projects]
    return jsonify({
        "status": "success",
        "organization": data
    }), 200


@orgs_bp.route('/organizations/<int:org_id>/members', methods=['GET'])
@orgs_bp.route('/v1/organizations/<int:org_id>/members', methods=['GET'])
def list_members(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    return jsonify({
        "status": "success",
        "members": [m.to_dict() for m in org.memberships]
    }), 200


@orgs_bp.route('/organizations/<int:org_id>/members', methods=['POST'])
@orgs_bp.route('/v1/organizations/<int:org_id>/members', methods=['POST'])
def add_member(org_id):
    """Add or invite a user to organization with a designated role."""
    org = db.session.get(Organization, org_id)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    role = (data.get('role') or 'Developer').strip()

    valid_roles = ['Owner', 'Admin', 'Security Engineer', 'Developer', 'Viewer']
    if role not in valid_roles:
        return jsonify({
            "status": "error",
            "message": f"Invalid role. Allowed roles: {', '.join(valid_roles)}"
        }), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Create user record with temporary password
        user = User(
            email=email,
            full_name=email.split('@')[0].capitalize(),
            is_active=True
        )
        user.set_password("TempPassword123!")
        db.session.add(user)
        db.session.flush()

    existing = Membership.query.filter_by(user_id=user.id, organization_id=org_id).first()
    if existing:
        existing.role = role
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": f"Updated {email} role to {role}",
            "membership": existing.to_dict()
        }), 200

    membership = Membership(
        user_id=user.id,
        organization_id=org_id,
        role=role,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(membership)
    db.session.commit()

    AuditLogger.log(
        org_id=org_id,
        action="member.added",
        resource_type="membership",
        resource_id=str(membership.id),
        details={"email": email, "role": role}
    )

    return jsonify({
        "status": "success",
        "message": f"Added {email} to organization with role {role}",
        "membership": membership.to_dict()
    }), 201


@orgs_bp.route('/organizations/<int:org_id>/members/<int:user_id>', methods=['DELETE'])
@orgs_bp.route('/v1/organizations/<int:org_id>/members/<int:user_id>', methods=['DELETE'])
def remove_member(org_id, user_id):
    membership = Membership.query.filter_by(user_id=user_id, organization_id=org_id).first()
    if not membership:
        return jsonify({"status": "error", "message": "Membership not found"}), 404

    db.session.delete(membership)
    db.session.commit()

    AuditLogger.log(
        org_id=org_id,
        action="member.removed",
        resource_type="membership",
        resource_id=str(user_id),
        details={"user_id": user_id}
    )

    return jsonify({
        "status": "success",
        "message": "Member removed from organization"
    }), 200
