"""
Scans routes
"""
import json
from flask import Blueprint, jsonify, request
from ..models.database import db, Scan, Project
from ..services.scan_service import scan_service

scans_bp = Blueprint('scans', __name__)


@scans_bp.route('/scans', methods=['GET'])
def list_scans():
    project_id = request.args.get('project_id', type=int)
    query = Scan.query
    if project_id:
        query = query.filter_by(project_id=project_id)

    scans = query.order_by(Scan.created_at.desc()).all()
    return jsonify({
        "status": "success",
        "count": len(scans),
        "scans": [s.to_dict() for s in scans]
    }), 200


@scans_bp.route('/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"status": "error", "message": f"Scan #{scan_id} not found"}), 404
    include_findings = request.args.get('include_findings', 'false').lower() == 'true'
    return jsonify({
        "status": "success",
        "scan": scan.to_dict(include_findings=include_findings)
    }), 200


@scans_bp.route('/scans/<int:scan_id>/findings', methods=['GET'])
def get_scan_findings(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"status": "error", "message": f"Scan #{scan_id} not found"}), 404

    severity = request.args.get('severity')
    owasp_category = request.args.get('owasp_category')
    cwe_id = request.args.get('cwe_id')
    status = request.args.get('status')
    search = request.args.get('search')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    findings, total = scan_service.get_findings_filtered(
        scan_id=scan.id,
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
        "scan_id": scan.id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "findings": [f.to_dict() for f in findings]
    }), 200


@scans_bp.route('/scans/upload', methods=['POST'])
def upload_scan_report():
    """
    Accepts OWASP ZAP JSON scan report either via multipart file upload or JSON payload.
    """
    project_id = None
    target_url = None
    scan_identifier = None
    raw_data = None

    if request.is_json:
        payload = request.get_json() or {}
        project_id = payload.get('project_id')
        target_url = payload.get('target_url')
        scan_identifier = payload.get('scan_identifier')
        raw_data = payload.get('report') or payload.get('report_json')
    elif 'file' in request.files:
        file = request.files['file']
        project_id = request.form.get('project_id', type=int)
        target_url = request.form.get('target_url')
        scan_identifier = request.form.get('scan_identifier')
        try:
            raw_content = file.read().decode('utf-8')
            raw_data = json.loads(raw_content)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Invalid JSON file: {str(e)}"}), 400
    else:
        return jsonify({"status": "error", "message": "No JSON payload or file provided."}), 400

    if not project_id:
        # Default to first available project or create one
        proj = Project.query.first()
        if proj:
            project_id = proj.id
        else:
            return jsonify({"status": "error", "message": "No project exists. Create a project first."}), 400

    try:
        scan = scan_service.process_zap_report(
            project_id=project_id,
            raw_report_data=raw_data,
            target_url=target_url,
            scan_identifier=scan_identifier
        )
        return jsonify({
            "status": "success",
            "message": "Scan report processed successfully",
            "scan": scan.to_dict(include_findings=True)
        }), 201
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to parse and process ZAP report: {str(e)}"
        }), 400


@scans_bp.route('/scans/simulate-preset', methods=['POST'])
def simulate_preset():
    """
    Simulates a scan ingestion using one of the pre-built reports:
    - 'juiceshop': High/Critical vulnerabilities (triggers BLOCK)
    - 'medium': Medium vulnerabilities only (triggers REVIEW)
    - 'clean': Hardened scan with zero high/critical (triggers PASS)
    """
    import os
    payload = request.get_json() or {}
    preset = payload.get('preset', 'juiceshop')
    project_id = payload.get('project_id')

    if not project_id:
        proj = Project.query.first()
        if proj:
            project_id = proj.id
        else:
            return jsonify({"status": "error", "message": "No project exists."}), 400

    filename_map = {
        'juiceshop': 'zap_juiceshop_scan.json',
        'clean': 'zap_clean_scan.json',
        'medium': 'zap_medium_scan.json'
    }

    filename = filename_map.get(preset, 'zap_juiceshop_scan.json')
    # Path relative to backend or repo root
    current_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))
    report_path = os.path.join(repo_root, 'reports', filename)

    if not os.path.exists(report_path):
        # Fallback to local reports directory
        report_path = os.path.join('reports', filename)

    if not os.path.exists(report_path):
        return jsonify({"status": "error", "message": f"Preset report file {filename} not found at {report_path}"}), 404

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)

        identifier = f"SIM-{preset.upper()}-{int(db.session.query(Scan).count()) + 1}"
        scan = scan_service.process_zap_report(
            project_id=project_id,
            raw_report_data=raw_data,
            target_url="http://localhost:3000 (Juice Shop)" if preset == "juiceshop" else "http://staging.internal:8080",
            scan_identifier=identifier
        )
        return jsonify({
            "status": "success",
            "message": f"Simulated {preset} scan successfully ingested",
            "scan": scan.to_dict(include_findings=True)
        }), 201
    except Exception as e:
        return jsonify({"status": "error", "message": f"Simulation failed: {str(e)}"}), 400


@scans_bp.route('/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"status": "error", "message": f"Scan #{scan_id} not found"}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"status": "success", "message": f"Scan #{scan_id} deleted"}), 200

