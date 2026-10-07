"""
Findings routes
Comprehensive vulnerability lifecycle management, risk acceptance, false positive triage,
and historical occurrence auditing.
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, jsonify, request
from ..models.database import (
    db, Finding, FindingOccurrence, RiskAcceptance, FalsePositive, User
)
from ..services.scan_service import scan_service
from ..security.auth import get_tenant_org_id, get_authenticated_user_context
from ..security.audit import AuditLogger

findings_bp = Blueprint('findings', __name__)

VALID_STATUSES = [
    'open', 'confirmed', 'in_progress', 'resolved', 'accepted',
    'false_positive', 'reopened', 'reviewed', 'fixed'
]


@findings_bp.route('/findings', methods=['GET'])
@findings_bp.route('/v1/findings', methods=['GET'])
def list_findings():
    project_id = request.args.get('project_id', type=int)
    scan_id = request.args.get('scan_id', type=int)
    severity = request.args.get('severity')
    owasp_category = request.args.get('owasp_category')
    cwe_id = request.args.get('cwe_id')
    status = request.args.get('status')
    search = request.args.get('search')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    org_id = get_tenant_org_id()

    findings, total = scan_service.get_findings_filtered(
        project_id=project_id,
        organization_id=org_id,
        scan_id=scan_id,
        severity=severity,
        owasp_category=owasp_category,
        cwe_id=cwe_id,
        status=status,
        search=search,
        page=page,
        per_page=per_page
    )

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "findings": [f.to_dict() for f in findings]
    }), 200


@findings_bp.route('/findings/<int:finding_id>', methods=['GET'])
@findings_bp.route('/v1/findings/<int:finding_id>', methods=['GET'])
def get_finding(finding_id):
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404

    data = finding.to_dict()
    # Include risk acceptance details if accepted
    if finding.risk_acceptance:
        data['risk_acceptance'] = finding.risk_acceptance.to_dict()
    if finding.false_positive_record:
        data['false_positive'] = finding.false_positive_record.to_dict()
    data['occurrence_count'] = len(finding.occurrences)

    return jsonify({
        "status": "success",
        "finding": data
    }), 200


@findings_bp.route('/findings/<int:finding_id>', methods=['PATCH'])
@findings_bp.route('/v1/findings/<int:finding_id>', methods=['PATCH'])
def update_finding_status(finding_id):
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404

    data = request.get_json() or {}
    new_status = (data.get('status') or '').strip().lower()

    if not new_status or new_status not in VALID_STATUSES:
        return jsonify({
            "status": "error",
            "message": f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}"
        }), 400

    old_status = finding.status
    finding.status = new_status
    if new_status in ('resolved', 'fixed'):
        finding.resolved_at = datetime.now(timezone.utc)
    elif old_status in ('resolved', 'fixed') and new_status not in ('resolved', 'fixed'):
        finding.resolved_at = None

    db.session.commit()

    user_ctx = get_authenticated_user_context()
    AuditLogger.log(
        org_id=finding.organization_id,
        action="finding.status_updated",
        resource_type="finding",
        resource_id=str(finding.id),
        user_id=user_ctx.get("user_id") if user_ctx else None,
        user_email=user_ctx.get("email") if user_ctx else "system",
        details={
            "finding_name": finding.name,
            "old_status": old_status,
            "new_status": new_status,
            "project_id": finding.project_id
        }
    )

    return jsonify({
        "status": "success",
        "message": f"Finding status updated to {new_status}",
        "finding": finding.to_dict()
    }), 200


@findings_bp.route('/findings/<int:finding_id>/accept-risk', methods=['POST'])
@findings_bp.route('/v1/findings/<int:finding_id>/accept-risk', methods=['POST'])
def accept_risk(finding_id):
    """
    Formal Risk Acceptance workflow.
    Requires business justification, approver identification, and expiration date.
    Suppresses finding from blocking release gates while risk acceptance is active.
    """
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404

    data = request.get_json() or {}
    justification = (data.get('justification') or '').strip()
    approved_by = (data.get('approved_by') or '').strip()
    days_valid = data.get('days_valid', 90)

    if not justification:
        return jsonify({"status": "error", "message": "Justification is required for risk acceptance"}), 400

    user_ctx = get_authenticated_user_context()
    user_id = user_ctx.get("user_id") if user_ctx else 1
    if not approved_by:
        approved_by = user_ctx.get("email", "Security Approver") if user_ctx else "Security Lead"

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=int(days_valid))

    # Remove existing risk acceptance if any
    if finding.risk_acceptance:
        db.session.delete(finding.risk_acceptance)
        db.session.flush()

    acceptance = RiskAcceptance(
        finding_id=finding.id,
        organization_id=finding.organization_id,
        user_id=user_id,
        justification=justification,
        approved_by=approved_by,
        expires_at=expires_at,
        status="Active",
        created_at=now
    )
    finding.status = "accepted"
    db.session.add(acceptance)
    db.session.commit()

    AuditLogger.log(
        org_id=finding.organization_id,
        action="finding.risk_accepted",
        resource_type="finding",
        resource_id=str(finding.id),
        user_id=user_id,
        user_email=approved_by,
        details={
            "finding_name": finding.name,
            "justification": justification,
            "approved_by": approved_by,
            "expires_at": expires_at.isoformat()
        }
    )

    return jsonify({
        "status": "success",
        "message": f"Risk accepted for finding #{finding_id} until {expires_at.strftime('%Y-%m-%d')}",
        "finding": finding.to_dict(),
        "risk_acceptance": acceptance.to_dict()
    }), 200


@findings_bp.route('/findings/<int:finding_id>/false-positive', methods=['POST'])
@findings_bp.route('/v1/findings/<int:finding_id>/false-positive', methods=['POST'])
def mark_false_positive(finding_id):
    """
    Mark finding as False Positive with mandatory technical justification.
    Prevents finding from triggering future release blocks for this signature.
    """
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404

    data = request.get_json() or {}
    reason = (data.get('reason') or '').strip()

    if not reason:
        return jsonify({"status": "error", "message": "Technical explanation is required to mark as false positive"}), 400

    user_ctx = get_authenticated_user_context()
    user_id = user_ctx.get("user_id") if user_ctx else 1
    user_email = user_ctx.get("email", "analyst") if user_ctx else "analyst"

    now = datetime.now(timezone.utc)
    if finding.false_positive_record:
        db.session.delete(finding.false_positive_record)
        db.session.flush()

    fp_record = FalsePositive(
        finding_id=finding.id,
        organization_id=finding.organization_id,
        user_id=user_id,
        reason=reason,
        created_at=now
    )
    finding.status = "false_positive"
    finding.confidence = "False Positive"
    db.session.add(fp_record)
    db.session.commit()

    AuditLogger.log(
        org_id=finding.organization_id,
        action="finding.false_positive",
        resource_type="finding",
        resource_id=str(finding.id),
        user_id=user_id,
        user_email=user_email,
        details={
            "finding_name": finding.name,
            "reason": reason
        }
    )

    return jsonify({
        "status": "success",
        "message": f"Finding #{finding_id} marked as False Positive",
        "finding": finding.to_dict(),
        "false_positive": fp_record.to_dict()
    }), 200


@findings_bp.route('/findings/<int:finding_id>/occurrences', methods=['GET'])
@findings_bp.route('/v1/findings/<int:finding_id>/occurrences', methods=['GET'])
def get_finding_occurrences(finding_id):
    """Returns the historical scan timeline and payloads for a recurring finding."""
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404

    occurrences = FindingOccurrence.query.filter_by(finding_id=finding.id).order_by(FindingOccurrence.created_at.desc()).all()
    return jsonify({
        "status": "success",
        "finding_id": finding_id,
        "finding_name": finding.name,
        "total_occurrences": len(occurrences),
        "occurrences": [o.to_dict() for o in occurrences]
    }), 200
