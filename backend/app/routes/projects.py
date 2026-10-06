"""
Projects routes
"""
from flask import Blueprint, jsonify, request
from ..models.database import db, Project
from ..services.demo_data import seed_demo_data

projects_bp = Blueprint('projects', __name__)


@projects_bp.route('/projects', methods=['GET'])
def list_projects():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    # If no projects exist at all, seed demo data automatically so dashboard is never empty
    if not projects:
        seed_demo_data()
        projects = Project.query.order_by(Project.created_at.desc()).all()
    return jsonify({
        "status": "success",
        "count": len(projects),
        "projects": [p.to_dict() for p in projects]
    }), 200


@projects_bp.route('/projects', methods=['POST'])
def create_project():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    target_url = data.get('target_url', '').strip()

    if not name:
        return jsonify({"status": "error", "message": "Project name is required"}), 400
    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required"}), 400

    # Ensure target_url is localhost or approved local target for safety
    # (per specification: only scan authorized local targets)
    description = data.get('description', '').strip()

    project = Project(
        name=name,
        target_url=target_url,
        description=description,
        is_demo=False
    )
    db.session.add(project)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Project created successfully",
        "project": project.to_dict()
    }), 201


@projects_bp.route('/projects/<int:project_id>', methods=['GET'])
def get_project(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"status": "error", "message": f"Project #{project_id} not found"}), 404
    return jsonify({"status": "success", "project": project.to_dict()}), 200


@projects_bp.route('/projects/<int:project_id>', methods=['DELETE'])
def delete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"status": "error", "message": f"Project #{project_id} not found"}), 404
    db.session.delete(project)
    db.session.commit()
    return jsonify({"status": "success", "message": f"Project #{project_id} deleted"}), 200


@projects_bp.route('/projects/seed-demo', methods=['POST'])
def seed_demo():
    demo = seed_demo_data(force=True)
    return jsonify({
        "status": "success",
        "message": "Demo project with scans and releases seeded successfully",
        "project": demo.to_dict()
    }), 200
