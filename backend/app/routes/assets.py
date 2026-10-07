"""
Asset Inventory & Attack Surface Management routes
Tracks discovered web assets, endpoints, API routes, criticality rankings,
and maps findings directly to individual endpoints.
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from ..models.database import db, Asset, Finding, Project
from ..security.auth import get_tenant_org_id, get_authenticated_user_context
from ..security.ssrf import validate_target_url
from ..security.audit import AuditLogger

assets_bp = Blueprint('assets', __name__)


@assets_bp.route('/assets', methods=['GET'])
@assets_bp.route('/v1/assets', methods=['GET'])
def list_assets():
    """List discovered attack surface assets with rich filters."""
    org_id = get_tenant_org_id()
    project_id = request.args.get('project_id', type=int)
    asset_type = request.args.get('asset_type')
    criticality = request.args.get('criticality')
    search = request.args.get('search')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    query = Asset.query
    if org_id:
        query = query.filter(Asset.organization_id == org_id)
    if project_id:
        query = query.filter(Asset.project_id == project_id)
    if asset_type and asset_type.lower() != 'all':
        query = query.filter(Asset.asset_type == asset_type.lower())
    if criticality and criticality.lower() != 'all':
        query = query.filter(Asset.criticality.ilike(criticality))
    if search:
        s = f"%{search}%"
        query = query.filter(
            (Asset.name.ilike(s)) |
            (Asset.url.ilike(s)) |
            (Asset.technology.ilike(s)) |
            (Asset.parameters.ilike(s))
        )

    total = query.count()
    assets = query.order_by(Asset.last_seen.desc()).offset((page - 1) * per_page).limit(per_page).all()

    # Enrich each asset with finding counts
    results = []
    for a in assets:
        d = a.to_dict()
        d['finding_count'] = Finding.query.filter_by(asset_id=a.id).count()
        results.append(d)

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "assets": results
    }), 200


@assets_bp.route('/assets', methods=['POST'])
@assets_bp.route('/v1/assets', methods=['POST'])
def create_asset():
    """Manually register an asset or API endpoint into inventory."""
    data = request.get_json() or {}
    project_id = data.get('project_id')
    name = (data.get('name') or '').strip()
    url = (data.get('url') or '').strip()
    http_method = (data.get('http_method') or 'GET').upper()
    asset_type = (data.get('asset_type') or 'endpoint').lower()
    criticality = (data.get('criticality') or 'Medium').capitalize()
    technology = (data.get('technology') or '').strip()
    parameters = (data.get('parameters') or '').strip()

    if not project_id:
        return jsonify({"status": "error", "message": "project_id is required"}), 400
    if not name:
        return jsonify({"status": "error", "message": "name is required"}), 400

    project = db.session.get(Project, project_id)
    if not project:
        return jsonify({"status": "error", "message": "Project not found"}), 404

    # Target URL SSRF validation
    if url:
        is_safe, ssrf_err = validate_target_url(url)
        if not is_safe:
            return jsonify({"status": "error", "message": f"Invalid asset URL: {ssrf_err}"}), 400

    now = datetime.now(timezone.utc)
    asset = Asset(
        organization_id=project.organization_id,
        project_id=project.id,
        asset_type=asset_type,
        name=name,
        url=url,
        http_method=http_method,
        criticality=criticality,
        technology=technology,
        parameters=parameters,
        first_seen=now,
        last_seen=now,
        created_at=now
    )
    db.session.add(asset)
    db.session.commit()

    user_ctx = get_authenticated_user_context()
    AuditLogger.log(
        org_id=project.organization_id,
        action="asset.created",
        resource_type="asset",
        resource_id=str(asset.id),
        user_id=user_ctx.get("user_id") if user_ctx else None,
        details={"name": name, "project_id": project_id, "criticality": criticality}
    )

    return jsonify({
        "status": "success",
        "message": f"Asset '{name}' created successfully",
        "asset": asset.to_dict()
    }), 201


@assets_bp.route('/assets/<int:asset_id>', methods=['GET'])
@assets_bp.route('/v1/assets/<int:asset_id>', methods=['GET'])
def get_asset(asset_id):
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404

    data = asset.to_dict()
    findings = Finding.query.filter_by(asset_id=asset.id).order_by(Finding.risk_score.desc()).all()
    data['findings'] = [f.to_dict() for f in findings]
    data['finding_count'] = len(findings)

    return jsonify({
        "status": "success",
        "asset": data
    }), 200


@assets_bp.route('/assets/<int:asset_id>', methods=['PATCH'])
@assets_bp.route('/v1/assets/<int:asset_id>', methods=['PATCH'])
def update_asset(asset_id):
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404

    data = request.get_json() or {}
    if 'criticality' in data:
        asset.criticality = data['criticality'].capitalize()
    if 'status' in data:
        asset.status = data['status'].lower()
    if 'technology' in data:
        asset.technology = data['technology']
    if 'parameters' in data:
        asset.parameters = data['parameters']

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Asset updated",
        "asset": asset.to_dict()
    }), 200


@assets_bp.route('/assets/<int:asset_id>', methods=['DELETE'])
@assets_bp.route('/v1/assets/<int:asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404

    db.session.delete(asset)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Asset #{asset_id} removed"
    }), 200
