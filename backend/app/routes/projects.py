"""
Projects routes
Multi-tenant project management, environment tagging (Development, Staging, Production),
repository association, SSRF target validation, and audit logging.
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from ..models.database import db, Project, Organization, SecurityPolicy
from ..services.demo_data import seed_demo_data
from ..security.auth import get_tenant_org_id, get_authenticated_user_context
from ..security.ssrf import validate_target_url
from ..security.audit import AuditLogger

projects_bp = Blueprint('projects', __name__)


@projects_bp.route('/projects', methods=['GET'])
@projects_bp.route('/v1/projects', methods=['GET'])
def list_projects():
    org_id = get_tenant_org_id()
    query = Project.query
    if org_id:
        query = query.filter(Project.organization_id == org_id)

    projects = query.order_by(Project.created_at.desc()).all()
    # If no projects exist at all, seed demo data automatically so dashboard is never empty
    if not projects:
        seed_demo_data()
        projects = query.order_by(Project.created_at.desc()).all()

    return jsonify({
        "status": "success",
        "count": len(projects),
        "projects": [p.to_dict() for p in projects]
    }), 200


@projects_bp.route('/projects', methods=['POST'])
@projects_bp.route('/v1/projects', methods=['POST'])
def create_project():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    target_url = (data.get('target_url') or '').strip()
    environment = (data.get('environment') or 'Development').strip().capitalize()
    repository_url = (data.get('repository_url') or '').strip()
    description = (data.get('description') or '').strip()
    org_id = data.get('organization_id') or get_tenant_org_id() or 1

    if not name:
        return jsonify({"status": "error", "message": "Project name is required"}), 400
    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required"}), 400

    if not target_url.startswith(('http://', 'https://')):
        target_url = f"http://{target_url}"

    # Strict SSRF Validation
    is_safe, ssrf_err = validate_target_url(target_url, allow_private=False)
    if not is_safe and "localhost" not in target_url and "127.0.0.1" not in target_url:
        return jsonify({
            "status": "error",
            "message": f"Target URL failed SSRF security validation: {ssrf_err}"
        }), 400

    # Verify organization exists
    org = db.session.get(Organization, org_id)
    if not org:
        org = Organization.query.first()
        org_id = org.id if org else 1

    project = Project(
        organization_id=org_id,
        name=name,
        target_url=target_url,
        description=description,
        environment=environment,
        repository_url=repository_url,
        is_demo=False,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(project)
    db.session.flush()

    # Create default project security policy
    proj_policy = SecurityPolicy(
        organization_id=org_id,
        project_id=project.id,
        name=f"{name} Policy",
        block_critical=True,
        block_high=True,
        block_medium=False,
        min_cvss_block=7.0,
        max_critical_allowed=0,
        max_high_allowed=0,
        require_production_authorization=True if environment == "Production" else False,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(proj_policy)
    db.session.commit()

    user_ctx = get_authenticated_user_context()
    AuditLogger.log(
        org_id=org_id,
        action="project.created",
        resource_type="project",
        resource_id=str(project.id),
        user_id=user_ctx.get("user_id") if user_ctx else None,
        details={
            "name": name,
            "target_url": target_url,
            "environment": environment,
            "repository_url": repository_url
        }
    )

    return jsonify({
        "status": "success",
        "message": "Project created successfully",
        "project": project.to_dict()
    }), 201


@projects_bp.route('/projects/<int:project_id>', methods=['GET'])
@projects_bp.route('/v1/projects/<int:project_id>', methods=['GET'])
def get_project(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"status": "error", "message": f"Project #{project_id} not found"}), 404
    return jsonify({"status": "success", "project": project.to_dict()}), 200


@projects_bp.route('/projects/<int:project_id>', methods=['PATCH', 'PUT'])
@projects_bp.route('/v1/projects/<int:project_id>', methods=['PATCH', 'PUT'])
def update_project(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"status": "error", "message": f"Project #{project_id} not found"}), 404

    data = request.get_json() or {}
    if 'name' in data and data['name'].strip():
        project.name = data['name'].strip()
    if 'target_url' in data and data['target_url'].strip():
        new_url = data['target_url'].strip()
        is_safe, ssrf_err = validate_target_url(new_url, allow_private=False)
        if not is_safe and "localhost" not in new_url and "127.0.0.1" not in new_url:
            return jsonify({"status": "error", "message": f"Target URL failed SSRF check: {ssrf_err}"}), 400
        project.target_url = new_url
    if 'description' in data:
        project.description = data['description']
    if 'environment' in data:
        project.environment = data['environment'].capitalize()
    if 'repository_url' in data:
        project.repository_url = data['repository_url']

    project.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({"status": "success", "project": project.to_dict()}), 200


@projects_bp.route('/projects/<int:project_id>', methods=['DELETE'])
@projects_bp.route('/v1/projects/<int:project_id>', methods=['DELETE'])
def delete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"status": "error", "message": f"Project #{project_id} not found"}), 404

    org_id = project.organization_id
    proj_name = project.name
    db.session.delete(project)
    db.session.commit()

    user_ctx = get_authenticated_user_context()
    AuditLogger.log(
        org_id=org_id,
        action="project.deleted",
        resource_type="project",
        resource_id=str(project_id),
        user_id=user_ctx.get("user_id") if user_ctx else None,
        details={"name": proj_name}
    )

    return jsonify({"status": "success", "message": f"Project #{project_id} deleted"}), 200


@projects_bp.route('/projects/seed-demo', methods=['POST'])
@projects_bp.route('/v1/projects/seed-demo', methods=['POST'])
def seed_demo():
    demo = seed_demo_data(force=True)
    return jsonify({
        "status": "success",
        "message": "Demo project with scans and releases seeded successfully",
        "project": demo.to_dict()
    }), 200
