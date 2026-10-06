"""
Releases routes
"""
from flask import Blueprint, jsonify, request
from ..models.database import db, Release, Scan, Project

releases_bp = Blueprint('releases', __name__)


@releases_bp.route('/releases', methods=['GET'])
def list_releases():
    project_id = request.args.get('project_id', type=int)
    query = Release.query
    if project_id:
        query = query.filter_by(project_id=project_id)

    releases = query.order_by(Release.created_at.desc()).all()
    result = []
    for r in releases:
        data = r.to_dict()
        scan = db.session.get(Scan, r.scan_id) if r.scan_id else None
        project = db.session.get(Project, r.project_id) if r.project_id else None
        data['scan_identifier'] = scan.scan_identifier if scan else 'N/A'
        data['security_score'] = scan.security_score if scan else None
        data['project_name'] = project.name if project else 'Unknown'
        data['severity_counts'] = {
            'critical': scan.critical_count,
            'high': scan.high_count,
            'medium': scan.medium_count,
            'low': scan.low_count,
            'informational': scan.informational_count,
        } if scan else None
        result.append(data)

    return jsonify({
        "status": "success",
        "count": len(result),
        "releases": result
    }), 200
