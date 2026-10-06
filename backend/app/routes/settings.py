"""
Settings routes
"""
import os
from flask import Blueprint, jsonify, request
from ..models.database import db, AppSettings

settings_bp = Blueprint('settings', __name__)


@settings_bp.route('/settings', methods=['GET'])
def get_settings():
    settings = AppSettings.query.first()
    if not settings:
        settings = AppSettings()
        db.session.add(settings)
        db.session.commit()

    data = settings.to_dict()
    # Provide system information without exposing raw secrets
    data['ai_api_key_configured'] = bool(os.environ.get('OPENAI_API_KEY'))
    data['scanner'] = 'OWASP ZAP'
    data['supported_environments'] = ['development', 'staging', 'production']
    data['supported_ci_cd'] = ['github_actions', 'gitlab_ci', 'jenkins']

    return jsonify({"status": "success", "settings": data}), 200


@settings_bp.route('/settings', methods=['PUT'])
def update_settings():
    settings = AppSettings.query.first()
    if not settings:
        settings = AppSettings()
        db.session.add(settings)

    payload = request.get_json() or {}
    rel_policy = payload.get('release_policy', {})

    if 'critical' in rel_policy:
        settings.release_policy_critical = rel_policy['critical'].upper()
    if 'high' in rel_policy:
        settings.release_policy_high = rel_policy['high'].upper()
    if 'medium' in rel_policy:
        settings.release_policy_medium = rel_policy['medium'].upper()
    if 'low' in rel_policy:
        settings.release_policy_low = rel_policy['low'].upper()
    if 'informational' in rel_policy:
        settings.release_policy_informational = rel_policy['informational'].upper()

    if 'ai_analysis_enabled' in payload:
        settings.ai_analysis_enabled = bool(payload['ai_analysis_enabled'])

    if 'environment' in payload:
        settings.environment = payload['environment']

    if 'ci_cd_provider' in payload:
        settings.ci_cd_provider = payload['ci_cd_provider']

    db.session.commit()

    data = settings.to_dict()
    data['ai_api_key_configured'] = bool(os.environ.get('OPENAI_API_KEY'))
    data['scanner'] = 'OWASP ZAP'

    return jsonify({
        "status": "success",
        "message": "Settings updated successfully",
        "settings": data
    }), 200
