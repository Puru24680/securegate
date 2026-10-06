"""
AI Analysis routes
"""
from flask import Blueprint, jsonify, request
from ..models.database import db, Finding
from ..services.ai_service import ai_service

ai_bp = Blueprint('ai', __name__)


@ai_bp.route('/ai/explain', methods=['POST'])
def explain_vulnerability():
    payload = request.get_json() or {}
    finding_id = payload.get('finding_id')

    if finding_id:
        finding = db.session.get(Finding, finding_id)
        if not finding:
            return jsonify({"status": "error", "message": f"Finding #{finding_id} not found"}), 404
        finding_data = finding.to_dict()
    else:
        finding_data = payload.get('finding')
        if not finding_data:
            return jsonify({"status": "error", "message": "Provide either 'finding_id' or 'finding' object."}), 400

    result = ai_service.explain_vulnerability(finding_data)
    return jsonify({
        "status": "success",
        "result": result
    }), 200
