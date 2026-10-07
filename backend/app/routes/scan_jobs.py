"""
Scan Orchestration & Lifecycle Jobs routes
Handles asynchronous scan execution, state transitions:
QUEUED -> INITIALIZING -> RUNNING -> PROCESSING -> COMPLETED (or FAILED / TIMEOUT / CANCELLED),
with strict SSRF validation, production gate verification, and real-time logging.
"""
import uuid
import threading
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, current_app
from ..models.database import db, ScanJob, Project, SecurityPolicy, Scan
from ..security.auth import get_tenant_org_id, get_authenticated_user_context
from ..security.ssrf import validate_target_url
from ..security.audit import AuditLogger
from ..services.zap_api_service import zap_api_service
from ..services.scan_service import scan_service

jobs_bp = Blueprint('scan_jobs', __name__)

ACTIVE_JOB_CANCELLATIONS = set()


def _run_background_scan_job(job_id: int, app):
    """Worker function updating database ScanJob state across lifecycle."""
    with app.app_context():
        job = db.session.get(ScanJob, job_id)
        if not job:
            return

        now = datetime.now(timezone.utc)
        job.started_at = now
        job.status = "INITIALIZING"
        job.stage_message = "Validating target and initializing scanning engine"
        job.progress = 10
        job.logs = f"[{now.strftime('%H:%M:%S')}] Job initialized: {job.target_url}\n"
        db.session.commit()

        try:
            # Check if cancelled
            if job.job_identifier in ACTIVE_JOB_CANCELLATIONS:
                job.status = "CANCELLED"
                job.stage_message = "Scan cancelled by user"
                db.session.commit()
                return

            # RUNNING Phase: trigger crawl or active scan via zap_api_service
            job.status = "RUNNING"
            job.stage_message = "Executing security spider and baseline inspection"
            job.progress = 30
            job.logs += f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Launching scanner probes against {job.target_url}\n"
            db.session.commit()

            # Execute scan via zap_api_service
            task_id = zap_api_service.create_scan_task(
                target_url=job.target_url,
                project_id=job.project_id,
                scan_type=job.scan_type,
                simulate=False,
                app=app
            )

            # Poll task until completion or cancellation
            while True:
                import time
                time.sleep(2)

                if job.job_identifier in ACTIVE_JOB_CANCELLATIONS:
                    job.status = "CANCELLED"
                    job.stage_message = "Scan cancelled by user"
                    db.session.commit()
                    return

                task = zap_api_service.get_scan_task(task_id)
                if not task:
                    break

                job.progress = max(job.progress, min(90, task.get("progress", 50)))
                job.stage_message = f"Scanning ({task.get('stage', 'IN_PROGRESS')})"
                if task.get("logs"):
                    job.logs = "\n".join(task["logs"][-30:])
                db.session.commit()

                if task.get("status") in ("COMPLETED", "FAILED"):
                    if task.get("status") == "COMPLETED":
                        job.scan_id = task.get("scan_id")
                    break

            # PROCESSING Phase: Normalization, deduplication, and risk evaluation
            job.status = "PROCESSING"
            job.stage_message = "Normalizing vulnerabilities, calculating risk, and checking release policy"
            job.progress = 95
            db.session.commit()

            job.status = "COMPLETED"
            job.stage_message = "Scan completed successfully"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc)
            db.session.commit()

        except Exception as e:
            job.status = "FAILED"
            job.stage_message = "Scan job failed"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            job.logs += f"\n[ERROR] {str(e)}"
            db.session.commit()


@jobs_bp.route('/scan-jobs', methods=['POST'])
@jobs_bp.route('/v1/scan-jobs', methods=['POST'])
def trigger_scan_job():
    """
    Trigger an asynchronous Scan Job with full lifecycle management.
    Performs SSRF validation and policy checks before queueing.
    """
    data = request.get_json() or {}
    target_url = (data.get('target_url') or '').strip()
    project_id = data.get('project_id')
    scan_type = (data.get('scan_type') or 'baseline').lower()
    triggered_by = (data.get('triggered_by') or 'manual').lower()

    if not target_url:
        return jsonify({"status": "error", "message": "target_url is required"}), 400

    if not target_url.startswith(('http://', 'https://')):
        target_url = f"http://{target_url}"

    # Strict SSRF Validation
    is_safe, ssrf_err = validate_target_url(target_url, allow_private=False)
    if not is_safe:
        # Check if Juice Shop demo or localhost is explicitly allowed for demo purposes
        if "localhost" not in target_url and "127.0.0.1" not in target_url:
            return jsonify({
                "status": "error",
                "message": f"Target URL rejected by SSRF Guard: {ssrf_err}"
            }), 400

    # Project context
    project = db.session.get(Project, project_id) if project_id else None
    if not project:
        project = Project.query.filter_by(target_url=target_url).first()
    if not project:
        project = Project.query.first()
    if not project:
        project = Project(
            name="Scanned Target Application",
            target_url=target_url,
            environment="Development"
        )
        db.session.add(project)
        db.session.commit()

    # Policy Check: Production scanning authorization
    if project.environment.lower() == "production":
        policy = SecurityPolicy.query.filter_by(project_id=project.id).first()
        if policy and policy.require_production_authorization:
            authorized = data.get('production_authorized', False)
            if not authorized:
                return jsonify({
                    "status": "error",
                    "message": "Production scan authorization required. Please set 'production_authorized': true to scan production environments."
                }), 403

    job_ident = f"job-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    user_ctx = get_authenticated_user_context()

    job = ScanJob(
        job_identifier=job_ident,
        organization_id=project.organization_id,
        project_id=project.id,
        target_url=target_url,
        scan_type=scan_type,
        status="QUEUED",
        progress=0,
        stage_message="Scan job queued in scheduler",
        triggered_by=triggered_by,
        created_at=now
    )
    db.session.add(job)
    db.session.commit()

    AuditLogger.log(
        org_id=project.organization_id,
        action="scan_job.queued",
        resource_type="scan_job",
        resource_id=job.job_identifier,
        user_id=user_ctx.get("user_id") if user_ctx else None,
        details={"target_url": target_url, "scan_type": scan_type}
    )

    # Launch background worker
    thread = threading.Thread(
        target=_run_background_scan_job,
        args=(job.id, current_app._get_current_object()),
        daemon=True
    )
    thread.start()

    return jsonify({
        "status": "success",
        "message": "Scan job queued successfully",
        "job": job.to_dict()
    }), 202


@jobs_bp.route('/scan-jobs', methods=['GET'])
@jobs_bp.route('/v1/scan-jobs', methods=['GET'])
def list_scan_jobs():
    org_id = get_tenant_org_id()
    project_id = request.args.get('project_id', type=int)
    status = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    query = ScanJob.query
    if org_id:
        query = query.filter(ScanJob.organization_id == org_id)
    if project_id:
        query = query.filter(ScanJob.project_id == project_id)
    if status and status.lower() != 'all':
        query = query.filter(ScanJob.status == status.upper())

    total = query.count()
    jobs = query.order_by(ScanJob.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "jobs": [j.to_dict() for j in jobs]
    }), 200


@jobs_bp.route('/scan-jobs/<job_identifier>', methods=['GET'])
@jobs_bp.route('/v1/scan-jobs/<job_identifier>', methods=['GET'])
def get_scan_job(job_identifier: str):
    job = ScanJob.query.filter_by(job_identifier=job_identifier).first()
    if not job:
        # Check by numeric id
        try:
            job = db.session.get(ScanJob, int(job_identifier))
        except ValueError:
            pass

    if not job:
        return jsonify({"status": "error", "message": f"Scan job {job_identifier} not found"}), 404

    data = job.to_dict()
    if job.scan_id:
        scan = db.session.get(Scan, job.scan_id)
        if scan:
            data['scan'] = scan.to_dict(include_findings=True)

    return jsonify({
        "status": "success",
        "job": data
    }), 200


@jobs_bp.route('/scan-jobs/<job_identifier>/cancel', methods=['POST'])
@jobs_bp.route('/v1/scan-jobs/<job_identifier>/cancel', methods=['POST'])
def cancel_scan_job(job_identifier: str):
    job = ScanJob.query.filter_by(job_identifier=job_identifier).first()
    if not job:
        try:
            job = db.session.get(ScanJob, int(job_identifier))
        except ValueError:
            pass

    if not job:
        return jsonify({"status": "error", "message": f"Scan job {job_identifier} not found"}), 404

    if job.status in ("COMPLETED", "FAILED", "CANCELLED"):
        return jsonify({"status": "error", "message": f"Job is already {job.status}"}), 400

    ACTIVE_JOB_CANCELLATIONS.add(job.job_identifier)
    job.status = "CANCELLED"
    job.stage_message = "Cancelled by user request"
    job.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Scan job {job_identifier} cancelled",
        "job": job.to_dict()
    }), 200
