from .health import health_bp
from .projects import projects_bp
from .scans import scans_bp
from .findings import findings_bp
from .dashboard import dashboard_bp
from .releases import releases_bp
from .reports import reports_bp
from .settings import settings_bp
from .ai import ai_bp

__all__ = [
    'health_bp',
    'projects_bp',
    'scans_bp',
    'findings_bp',
    'dashboard_bp',
    'releases_bp',
    'reports_bp',
    'settings_bp',
    'ai_bp',
]
