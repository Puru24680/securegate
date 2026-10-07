"""
Audit Trail routes
Provides immutable, chronological records of all security-sensitive operations,
logins, vulnerability status modifications, risk acceptances, and policy overrides.
"""
from flask import Blueprint, jsonify, request
from ..models.database import db, AuditLog
from ..security.auth import get_tenant_org_id

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/audit-logs', methods=['GET'])
@audit_bp.route('/v1/audit-logs', methods=['GET'])
def list_audit_logs():
    org_id = get_tenant_org_id()
    action = request.args.get('action')
    resource_type = request.args.get('resource_type')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    query = AuditLog.query
    if org_id:
        query = query.filter(AuditLog.organization_id == org_id)
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "audit_logs": [log.to_dict() for log in logs]
    }), 200
