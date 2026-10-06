"""
SecureGate Backend - Application Factory
"""
import os
from flask import Flask
from flask_cors import CORS
from .models.database import db, init_db
from .routes.health import health_bp
from .routes.projects import projects_bp
from .routes.scans import scans_bp
from .routes.findings import findings_bp
from .routes.dashboard import dashboard_bp
from .routes.releases import releases_bp
from .routes.reports import reports_bp
from .routes.settings import settings_bp
from .routes.ai import ai_bp


def create_app(config=None):
    app = Flask(__name__)

    # Configuration
    default_db_dir = '/tmp' if os.environ.get('VERCEL') else os.path.dirname(os.path.dirname(__file__))
    default_db_path = os.path.join(default_db_dir, 'securegate.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f"sqlite:///{default_db_path}")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securegate-dev-secret-2024')
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

    if config:
        app.config.update(config)

    # Extensions
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(health_bp, url_prefix='/api')
    app.register_blueprint(projects_bp, url_prefix='/api')
    app.register_blueprint(scans_bp, url_prefix='/api')
    app.register_blueprint(findings_bp, url_prefix='/api')
    app.register_blueprint(dashboard_bp, url_prefix='/api')
    app.register_blueprint(releases_bp, url_prefix='/api')
    app.register_blueprint(reports_bp, url_prefix='/api')
    app.register_blueprint(settings_bp, url_prefix='/api')
    app.register_blueprint(ai_bp, url_prefix='/api')

    # Initialize database
    with app.app_context():
        init_db(app)

    return app
