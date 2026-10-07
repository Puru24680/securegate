"""
OWASP ZAP API Routes
Provides endpoints for connecting with OWASP ZAP daemon,
initiating live active/spider scans, monitoring progress, and importing findings.
"""
from flask import Blueprint, jsonify, request, current_app
from ..services.zap_api_service import zap_api_service
from ..models.database import db, Scan

zap_bp = Blueprint('zap', __name__)


@zap_bp.route('/zap/health', methods=['GET'])
def zap_health():
    """Check connectivity to OWASP ZAP daemon."""
    zap_url = request.args.get('zap_url')
    api_key = request.args.get('api_key')
    health = zap_api_service.check_daemon_health(zap_url=zap_url, api_key=api_key)
    return jsonify({
        "status": "success",
        "daemon": health
    }), 200


@zap_bp.route('/zap/scan', methods=['POST'])
def start_zap_scan():
    """
    Launch a live or simulated ZAP scan task.
    Payload:
      target_url: str (required)
      project_id: int (optional)
      scan_type: "full" | "spider" | "active" (default "full")
      zap_url: str (optional)
      api_key: str (optional)
      simulate: bool (optional, forces simulation if True or daemon offline)
    """
    payload = request.get_json() or {}
    target_url = payload.get('target_url')
    if not target_url:
        return jsonify({"status": "error", "message": "target_url is required"}), 400

    target_url = str(target_url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"https://{target_url}"

    project_id = payload.get('project_id')
    scan_type = payload.get('scan_type', 'full')
    zap_url = payload.get('zap_url')
    api_key = payload.get('api_key')
    simulate = bool(payload.get('simulate', False))

    task_id = zap_api_service.create_scan_task(
        target_url=target_url,
        project_id=project_id,
        scan_type=scan_type,
        zap_url=zap_url,
        api_key=api_key,
        simulate=simulate,
        app=current_app._get_current_object()
    )

    return jsonify({
        "status": "success",
        "message": "Scan task initialized",
        "task_id": task_id,
        "target_url": target_url
    }), 202


@zap_bp.route('/zap/tasks/<task_id>', methods=['GET'])
def get_zap_task_status(task_id: str):
    """Query progress and logs for a running ZAP scan task."""
    task = zap_api_service.get_scan_task(task_id)
    if not task:
        return jsonify({"status": "error", "message": f"Task {task_id} not found"}), 404

    result = dict(task)
    # If completed and scan_id is present, attach the scan model summary
    if task.get("scan_id"):
        scan = db.session.get(Scan, task["scan_id"])
        if scan:
            result["scan"] = scan.to_dict(include_findings=True)

    return jsonify({
        "status": "success",
        "task": result
    }), 200


@zap_bp.route('/zap/quickstart', methods=['GET'])
def get_quickstart_instructions():
    """Returns copy-pasteable instructions for running OWASP ZAP daemon."""
    docker_command = "docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true"
    cli_command = "zap.bat -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true"
    return jsonify({
        "status": "success",
        "docker_command": docker_command,
        "cli_command": cli_command,
        "default_url": "http://localhost:8080",
        "documentation": "https://www.zaproxy.org/docs/api/"
    }), 200
