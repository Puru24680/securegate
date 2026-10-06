"""
Dashboard routes
Aggregates security posture metrics, risk over time, OWASP distribution, and release gating.
"""
from flask import Blueprint, jsonify, request
from ..models.database import db, Project, Scan, Finding, Release, AppSettings
from ..security.severity_engine import SEVERITY_ORDER
from ..services.demo_data import seed_demo_data

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard', methods=['GET'])
def get_dashboard_data():
    project_id = request.args.get('project_id', type=int)
    scan_id = request.args.get('scan_id', type=int)

    # If no projects exist, seed demo data automatically
    all_projects = Project.query.all()
    if not all_projects:
        seed_demo_data()
        all_projects = Project.query.all()

    # Select project
    if project_id:
        project = db.session.get(Project, project_id)
    else:
        project = all_projects[0] if all_projects else None

    if not project:
        return jsonify({
            "status": "success",
            "empty": True,
            "message": "No projects or scans available."
        }), 200

    # Scans for this project
    scans = Scan.query.filter_by(project_id=project.id).order_by(Scan.created_at.desc()).all()

    # Active scan selection (specific scan_id or latest)
    active_scan = None
    if scan_id:
        active_scan = db.session.get(Scan, scan_id)
        if active_scan and active_scan.project_id != project.id:
            active_scan = None

    if not active_scan:
        active_scan = scans[0] if scans else None

    # Current release policy
    settings = AppSettings.query.first()
    policy = settings.to_dict()['release_policy'] if settings else {}

    # Active scan findings
    findings = []
    if active_scan:
        findings = Finding.query.filter_by(scan_id=active_scan.id).all()

    # Severity distribution for active scan
    sev_distribution = {s: 0 for s in SEVERITY_ORDER}
    owasp_distribution = {}
    cwe_distribution = {}

    for f in findings:
        sev_distribution[f.severity] = sev_distribution.get(f.severity, 0) + 1
        cat = f.owasp_category or "Unmapped"
        owasp_distribution[cat] = owasp_distribution.get(cat, 0) + 1
        if f.cwe_id and f.cwe_id != "N/A":
            cwe_distribution[f.cwe_id] = cwe_distribution.get(f.cwe_id, 0) + 1

    # Historical risk trend (scans chronological)
    risk_over_time = []
    for s in reversed(scans):
        risk_over_time.append({
            "scan_id": s.id,
            "scan_identifier": s.scan_identifier,
            "date": s.created_at.strftime("%b %d, %H:%M") if s.created_at else "",
            "security_score": s.security_score,
            "release_status": s.release_status,
            "total_findings": s.total_findings,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "informational": s.informational_count,
        })

    # Recent releases
    recent_releases = Release.query.filter_by(project_id=project.id).order_by(Release.created_at.desc()).limit(5).all()

    # Match release gate decision strictly for the active scan
    active_release = Release.query.filter_by(scan_id=active_scan.id).first() if active_scan else None
    if active_release:
        gate_status = active_release.status
        gate_reason = active_release.reason
        gate_version = active_release.version
        blocking_findings = active_release.blocking_findings
        review_findings = active_release.review_findings
    elif active_scan:
        from ..security.severity_engine import calculate_release_status
        calc_status, calc_reason, b_count, r_count = calculate_release_status(findings, policy)
        gate_status = active_scan.release_status or calc_status
        gate_reason = calc_reason
        gate_version = "v1.0.0"
        blocking_findings = b_count
        review_findings = r_count
    else:
        gate_status = "PASS"
        gate_reason = "No security findings recorded."
        gate_version = "v1.0.0"
        blocking_findings = 0
        review_findings = 0

    # OWASP distribution array formatted for charts
    owasp_chart_data = [
        {"category": k.split(' - ')[-1] if ' - ' in k else k, "fullName": k, "count": v}
        for k, v in sorted(owasp_distribution.items(), key=lambda x: x[1], reverse=True)
    ]

    # Severity chart data
    sev_chart_data = [
        {"severity": s, "count": sev_distribution.get(s, 0)}
        for s in SEVERITY_ORDER
    ]

    return jsonify({
        "status": "success",
        "empty": False,
        "project": project.to_dict(),
        "active_scan_id": active_scan.id if active_scan else None,
        "latest_scan": active_scan.to_dict() if active_scan else None,
        "security_score": active_scan.security_score if active_scan else 100.0,
        "release_gate": {
            "status": gate_status,
            "reason": gate_reason,
            "version": gate_version,
            "blocking_findings": blocking_findings,
            "review_findings": review_findings,
        },
        "metrics": {
            "critical": active_scan.critical_count if active_scan else 0,
            "high": active_scan.high_count if active_scan else 0,
            "medium": active_scan.medium_count if active_scan else 0,
            "low": active_scan.low_count if active_scan else 0,
            "informational": active_scan.informational_count if active_scan else 0,
            "total_findings": active_scan.total_findings if active_scan else 0,
        },
        "charts": {
            "severity_distribution": sev_chart_data,
            "risk_over_time": risk_over_time,
            "owasp_coverage": owasp_chart_data,
        },
        "recent_scans": [s.to_dict() for s in scans[:5]],
        "recent_releases": [r.to_dict() for r in recent_releases],
        "release_policy": policy,
    }), 200
