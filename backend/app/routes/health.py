"""
Health check route
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify
from ..models.database import db

health_bp = Blueprint('health', __name__)


@health_bp.route('/health', methods=['GET'])
def health_check():
    db_status = "connected"
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    return jsonify({
        "status": "healthy",
        "service": "SecureGate Pre-Release Security Gate API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_status
    }), 200
