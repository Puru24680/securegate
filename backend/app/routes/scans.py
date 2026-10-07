"""
Scans routes
"""
import json
from flask import Blueprint, jsonify, request
from ..models.database import db, Scan, Project
from ..services.scan_service import scan_service

from ..security.auth import get_tenant_org_id, get_authenticated_user_context

scans_bp = Blueprint('scans', __name__)


@scans_bp.route('/scans', methods=['GET'])
@scans_bp.route('/v1/scans', methods=['GET'])
def list_scans():
    project_id = request.args.get('project_id', type=int)
    org_id = get_tenant_org_id()
    query = Scan.query
    if org_id:
        query = query.filter_by(organization_id=org_id)
    if project_id:
        query = query.filter_by(project_id=project_id)

    scans = query.order_by(Scan.created_at.desc()).all()
    return jsonify({
        "status": "success",
        "count": len(scans),
        "scans": [s.to_dict() for s in scans]
    }), 200


@scans_bp.route('/scans/<int:scan_id>', methods=['GET'])
@scans_bp.route('/v1/scans/<int:scan_id>', methods=['GET'])
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
@scans_bp.route('/v1/scans/upload', methods=['POST'])
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
            raw_bytes = file.read()
            raw_content = None
            for enc in ['utf-8-sig', 'utf-8', 'latin-1']:
                try:
                    raw_content = raw_bytes.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if not raw_content:
                raw_content = raw_bytes.decode('utf-8', errors='ignore')
            raw_data = json.loads(raw_content)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Invalid JSON file: {str(e)}"}), 400
    else:
        return jsonify({"status": "error", "message": "No JSON payload or file provided."}), 400

    if not project_id or not db.session.get(Project, project_id):
        # Default to first available project or create one
        proj = Project.query.first()
        if not proj:
            proj = Project(
                name="OWASP Juice Shop",
                target_url=target_url or "http://localhost:3000",
                description="Default web application target for pre-release security gating.",
                is_demo=True
            )
            db.session.add(proj)
            db.session.commit()
        project_id = proj.id

    try:
        user_ctx = get_authenticated_user_context()
        scan = scan_service.process_zap_report(
            project_id=project_id,
            raw_report_data=raw_data,
            target_url=target_url,
            scan_identifier=scan_identifier,
            triggered_by="upload",
            user_id=user_ctx.get("user_id") if user_ctx else None,
            user_email=user_ctx.get("email") if user_ctx else "analyst"
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

    if not project_id or not db.session.get(Project, project_id):
        proj = Project.query.first()
        if not proj:
            proj = Project(
                name="OWASP Juice Shop",
                target_url="http://localhost:3000",
                description="Default web application target for pre-release security gating.",
                is_demo=True
            )
            db.session.add(proj)
            db.session.commit()
        project_id = proj.id

    filename_map = {
        'juiceshop': 'zap_juiceshop_scan.json',
        'clean': 'zap_clean_scan.json',
        'medium': 'zap_medium_scan.json'
    }

    filename = filename_map.get(preset, 'zap_juiceshop_scan.json')
    current_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))

    candidate_paths = [
        os.path.join(repo_root, 'reports', filename),
        os.path.join('reports', filename),
        os.path.join(os.getcwd(), 'reports', filename),
        os.path.join(current_dir, '..', '..', 'reports', filename),
    ]

    raw_data = None
    for p in candidate_paths:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    raw_data = json.load(f)
                    break
            except Exception:
                pass

    if not raw_data:
        # Built-in fallback ZAP report format so preset simulation is 100% resilient on Vercel
        if preset == 'juiceshop':
            from ..services.demo_data import SAMPLE_JUICESHOP_FINDINGS
            raw_data = {
                "@version": "2.14.0",
                "site": [{
                    "@name": "http://localhost:3000",
                    "alerts": [
                        {
                            "alert": f["name"],
                            "riskcode": "3" if f["severity"] in ["Critical", "High"] else "2" if f["severity"] == "Medium" else "1",
                            "confidence": "3" if f["confidence"] == "High" else "2",
                            "desc": f["description"],
                            "url": f["url"],
                            "param": f["parameter"],
                            "evidence": f["evidence"],
                            "cweid": f["cwe_id"].replace("CWE-", "") if f.get("cwe_id") else "",
                            "solution": f["solution"],
                            "reference": f["reference"]
                        }
                        for f in SAMPLE_JUICESHOP_FINDINGS
                    ]
                }]
            }
        elif preset == 'clean':
            raw_data = {
                "@version": "2.14.0",
                "site": [{
                    "@name": "https://staging.internal.secgate.io",
                    "alerts": [
                        {
                            "alert": "Cookie No HttpOnly Flag",
                            "riskcode": "1",
                            "confidence": "3",
                            "desc": "A cookie has been set without HttpOnly.",
                            "url": "https://staging.internal.secgate.io/api/auth",
                            "param": "tracking_id",
                            "cweid": "1004",
                            "solution": "Set HttpOnly flag"
                        }
                    ]
                }]
            }
        else:
            raw_data = {
                "@version": "2.14.0",
                "site": [{
                    "@name": "https://staging.internal.secgate.io",
                    "alerts": [
                        {
                            "alert": "Absence of Anti-CSRF Tokens",
                            "riskcode": "2",
                            "confidence": "2",
                            "desc": "No CSRF tokens were found in forms.",
                            "url": "https://staging.internal.secgate.io/profile",
                            "param": "username",
                            "cweid": "352",
                            "solution": "Implement CSRF tokens"
                        }
                    ]
                }]
            }

    try:
        identifier = f"SIM-{preset.upper()}-{int(db.session.query(Scan).count()) + 1}"
        scan = scan_service.process_zap_report(
            project_id=project_id,
            raw_report_data=raw_data,
            target_url="http://localhost:3000" if preset == "juiceshop" else "https://staging.internal.secgate.io",
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

