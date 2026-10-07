"""
SecureGate Database Models
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Initialize database and create tables."""
    db.create_all()
    _seed_default_settings()
    _seed_default_project()


def _seed_default_settings():
    """Create default settings if they don't exist."""
    if not AppSettings.query.first():
        defaults = AppSettings(
            release_policy_critical='BLOCK',
            release_policy_high='BLOCK',
            release_policy_medium='REVIEW',
            release_policy_low='PASS',
            release_policy_informational='PASS',
            ai_analysis_enabled=True,
            environment='development',
            ci_cd_provider='github_actions',
        )
        db.session.add(defaults)
        db.session.commit()


def _seed_default_project():
    """Ensure at least one default project and initial demo dataset exists."""
    if not Project.query.first():
        p = Project(
            name="OWASP Juice Shop",
            target_url="http://localhost:3000",
            description="Default web application target for pre-release security gating.",
            is_demo=True
        )
        db.session.add(p)
        db.session.commit()

        # Seed initial demo scans so serverless instances on Vercel are never empty
        try:
            from ..services.demo_data import seed_demo_data
            seed_demo_data()
        except Exception:
            pass


class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    target_url = db.Column(db.String(500), nullable=False)
    is_demo = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))

    scans = db.relationship('Scan', backref='project', lazy=True, cascade='all, delete-orphan')
    releases = db.relationship('Release', backref='project', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'target_url': self.target_url,
            'is_demo': self.is_demo,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'scan_count': len(self.scans),
            'latest_scan': self.scans[-1].to_dict() if self.scans else None,
        }


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    scan_identifier = db.Column(db.String(100), unique=True, nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Integer, default=0)  # seconds
    security_score = db.Column(db.Float, default=0.0)
    release_status = db.Column(db.String(20), default='PENDING')  # PASS, REVIEW, BLOCK, PENDING
    total_findings = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    informational_count = db.Column(db.Integer, default=0)
    raw_report_path = db.Column(db.String(500), nullable=True)
    scanner = db.Column(db.String(50), default='OWASP ZAP')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')
    releases = db.relationship('Release', backref='scan', lazy=True, cascade='all, delete-orphan')

    def to_dict(self, include_findings=False):
        data = {
            'id': self.id,
            'project_id': self.project_id,
            'scan_identifier': self.scan_identifier,
            'target_url': self.target_url,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'security_score': round(self.security_score, 1),
            'release_status': self.release_status,
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'informational_count': self.informational_count,
            'scanner': self.scanner,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
        if include_findings:
            data['findings'] = [f.to_dict() for f in self.findings]
        return data


class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    name = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default='')
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low, Informational
    confidence = db.Column(db.String(20), default='Medium')  # High, Medium, Low
    url = db.Column(db.String(1000), default='')
    method = db.Column(db.String(20), default='GET')
    parameter = db.Column(db.String(200), default='')
    evidence = db.Column(db.Text, default='')
    solution = db.Column(db.Text, default='')
    reference = db.Column(db.Text, default='')
    cwe_id = db.Column(db.String(20), default='N/A')
    owasp_category = db.Column(db.String(100), default='Unmapped')
    owasp_year = db.Column(db.String(10), default='2021')
    risk_score = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(30), default='open')  # open, reviewed, accepted, fixed
    plugin_id = db.Column(db.String(50), default='')
    alert_ref = db.Column(db.String(50), default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'solution': self.solution,
            'reference': self.reference,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'owasp_year': self.owasp_year,
            'risk_score': round(self.risk_score, 1),
            'status': self.status,
            'plugin_id': self.plugin_id,
            'alert_ref': self.alert_ref,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Release(db.Model):
    __tablename__ = 'releases'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)
    version = db.Column(db.String(50), default='')
    status = db.Column(db.String(20), nullable=False)  # PASS, REVIEW, BLOCK
    reason = db.Column(db.Text, default='')
    blocking_findings = db.Column(db.Integer, default=0)
    review_findings = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'scan_id': self.scan_id,
            'version': self.version,
            'status': self.status,
            'reason': self.reason,
            'blocking_findings': self.blocking_findings,
            'review_findings': self.review_findings,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class AppSettings(db.Model):
    __tablename__ = 'app_settings'

    id = db.Column(db.Integer, primary_key=True)
    release_policy_critical = db.Column(db.String(20), default='BLOCK')
    release_policy_high = db.Column(db.String(20), default='BLOCK')
    release_policy_medium = db.Column(db.String(20), default='REVIEW')
    release_policy_low = db.Column(db.String(20), default='PASS')
    release_policy_informational = db.Column(db.String(20), default='PASS')
    ai_analysis_enabled = db.Column(db.Boolean, default=True)
    environment = db.Column(db.String(30), default='development')
    ci_cd_provider = db.Column(db.String(30), default='github_actions')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'release_policy': {
                'critical': self.release_policy_critical,
                'high': self.release_policy_high,
                'medium': self.release_policy_medium,
                'low': self.release_policy_low,
                'informational': self.release_policy_informational,
            },
            'ai_analysis_enabled': self.ai_analysis_enabled,
            'environment': self.environment,
            'ci_cd_provider': self.ci_cd_provider,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
