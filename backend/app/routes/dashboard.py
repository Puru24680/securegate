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
    latest_scan = scans[0] if scans else None

    # Latest findings
    findings = []
    if latest_scan:
        findings = Finding.query.filter_by(scan_id=latest_scan.id).all()

    # Severity distribution for latest scan
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
        })

    # Recent releases
    recent_releases = Release.query.filter_by(project_id=project.id).order_by(Release.created_at.desc()).limit(5).all()

    # Latest release gating
    latest_release = recent_releases[0] if recent_releases else None

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

    # Current release policy
    settings = AppSettings.query.first()
    policy = settings.to_dict()['release_policy'] if settings else {}

    return jsonify({
        "status": "success",
        "empty": False,
        "project": project.to_dict(),
        "latest_scan": latest_scan.to_dict() if latest_scan else None,
        "security_score": latest_scan.security_score if latest_scan else 100.0,
        "release_gate": {
            "status": latest_scan.release_status if latest_scan else "PASS",
            "reason": latest_release.reason if latest_release else "No active release block.",
            "version": latest_release.version if latest_release else "v1.0.0",
            "blocking_findings": latest_release.blocking_findings if latest_release else 0,
            "review_findings": latest_release.review_findings if latest_release else 0,
        },
        "metrics": {
            "critical": latest_scan.critical_count if latest_scan else 0,
            "high": latest_scan.high_count if latest_scan else 0,
            "medium": latest_scan.medium_count if latest_scan else 0,
            "low": latest_scan.low_count if latest_scan else 0,
            "informational": latest_scan.informational_count if latest_scan else 0,
            "total_findings": latest_scan.total_findings if latest_scan else 0,
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
