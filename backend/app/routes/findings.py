"""
Findings routes
"""
from flask import Blueprint, jsonify, request
from ..models.database import db, Finding
from ..services.scan_service import scan_service

findings_bp = Blueprint('findings', __name__)


@findings_bp.route('/findings', methods=['GET'])
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

    findings, total = scan_service.get_findings_filtered(
        project_id=project_id,
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
def get_finding(finding_id):
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404
    return jsonify({
        "status": "success",
        "finding": finding.to_dict()
    }), 200


@findings_bp.route('/findings/<int:finding_id>', methods=['PATCH'])
def update_finding_status(finding_id):
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404

    data = request.get_json() or {}
    new_status = data.get('status')
    valid_statuses = ['open', 'reviewed', 'accepted', 'fixed']

    if new_status and new_status in valid_statuses:
        finding.status = new_status
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": f"Finding status updated to {new_status}",
            "finding": finding.to_dict()
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        }), 400
