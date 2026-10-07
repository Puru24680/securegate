"""
Security Policies & Release Gate Governance routes
Configures deterministic policy thresholds (block Critical/High/Medium, CVSS cutoffs,
maximum allowable findings per severity tier, production authorization).
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from ..models.database import db, SecurityPolicy, Project, Organization
from ..security.auth import get_tenant_org_id, get_authenticated_user_context
from ..security.audit import AuditLogger

policies_bp = Blueprint('policies', __name__)


@policies_bp.route('/policies', methods=['GET'])
@policies_bp.route('/v1/policies', methods=['GET'])
def list_policies():
    org_id = get_tenant_org_id()
    project_id = request.args.get('project_id', type=int)

    query = SecurityPolicy.query
    if org_id:
        query = query.filter(SecurityPolicy.organization_id == org_id)
    if project_id:
        query = query.filter((SecurityPolicy.project_id == project_id) | (SecurityPolicy.project_id == None))

    policies = query.order_by(SecurityPolicy.id.asc()).all()
    return jsonify({
        "status": "success",
        "policies": [p.to_dict() for p in policies]
    }), 200


@policies_bp.route('/policies', methods=['POST'])
@policies_bp.route('/v1/policies', methods=['POST'])
def create_policy():
    data = request.get_json() or {}
    name = (data.get('name') or 'Custom Security Policy').strip()
    project_id = data.get('project_id')
    org_id = data.get('organization_id') or get_tenant_org_id() or 1

    policy = SecurityPolicy(
        organization_id=org_id,
        project_id=project_id,
        name=name,
        block_critical=data.get('block_critical', True),
        block_high=data.get('block_high', True),
        block_medium=data.get('block_medium', False),
        min_cvss_block=float(data.get('min_cvss_block', 7.0)),
        max_critical_allowed=int(data.get('max_critical_allowed', 0)),
        max_high_allowed=int(data.get('max_high_allowed', 0)),
        require_production_authorization=data.get('require_production_authorization', True),
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(policy)
    db.session.commit()

    user_ctx = get_authenticated_user_context()
    AuditLogger.log(
        org_id=org_id,
        action="policy.created",
        resource_type="security_policy",
        resource_id=str(policy.id),
        user_id=user_ctx.get("user_id") if user_ctx else None,
        details={"name": name, "project_id": project_id}
    )

    return jsonify({
        "status": "success",
        "message": f"Security policy '{name}' created successfully",
        "policy": policy.to_dict()
    }), 201


@policies_bp.route('/policies/<int:policy_id>', methods=['GET'])
@policies_bp.route('/v1/policies/<int:policy_id>', methods=['GET'])
def get_policy(policy_id):
    policy = db.session.get(SecurityPolicy, policy_id)
    if not policy:
        return jsonify({"status": "error", "message": "Policy not found"}), 404

    return jsonify({
        "status": "success",
        "policy": policy.to_dict()
    }), 200


@policies_bp.route('/policies/<int:policy_id>', methods=['PUT', 'PATCH'])
@policies_bp.route('/v1/policies/<int:policy_id>', methods=['PUT', 'PATCH'])
def update_policy(policy_id):
    policy = db.session.get(SecurityPolicy, policy_id)
    if not policy:
        return jsonify({"status": "error", "message": "Policy not found"}), 404

    data = request.get_json() or {}
    if 'name' in data:
        policy.name = data['name']
    if 'block_critical' in data:
        policy.block_critical = bool(data['block_critical'])
    if 'block_high' in data:
        policy.block_high = bool(data['block_high'])
    if 'block_medium' in data:
        policy.block_medium = bool(data['block_medium'])
    if 'min_cvss_block' in data:
        policy.min_cvss_block = float(data['min_cvss_block'])
    if 'max_critical_allowed' in data:
        policy.max_critical_allowed = int(data['max_critical_allowed'])
    if 'max_high_allowed' in data:
        policy.max_high_allowed = int(data['max_high_allowed'])
    if 'require_production_authorization' in data:
        policy.require_production_authorization = bool(data['require_production_authorization'])

    policy.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    user_ctx = get_authenticated_user_context()
    AuditLogger.log(
        org_id=policy.organization_id,
        action="policy.updated",
        resource_type="security_policy",
        resource_id=str(policy.id),
        user_id=user_ctx.get("user_id") if user_ctx else None,
        details={"name": policy.name, "min_cvss_block": policy.min_cvss_block}
    )

    return jsonify({
        "status": "success",
        "message": "Policy updated successfully",
        "policy": policy.to_dict()
    }), 200
