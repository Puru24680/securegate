"""
SecureGate Enterprise Relational Database Models
Multi-tenant, role-based architecture with asset inventory, canonical finding lifecycle,
audit logging, risk acceptances, and scan orchestration.
"""
from datetime import datetime, timezone
import json
import bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Initialize database and create tables with baseline seed data."""
    db.create_all()
    _auto_migrate()
    _seed_default_organization_and_user()
    _seed_default_settings()
    _seed_default_project()


def _auto_migrate():
    """Safely apply schema migrations to existing SQLite/Postgres tables if columns are missing."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())

    migrations = [
        ("projects", "organization_id", "INTEGER DEFAULT 1"),
        ("projects", "environment", "VARCHAR(50) DEFAULT 'Development'"),
        ("projects", "repository_url", "VARCHAR(500) DEFAULT ''"),
        ("scans", "organization_id", "INTEGER DEFAULT 1"),
        ("findings", "fingerprint", "VARCHAR(64)"),
        ("findings", "organization_id", "INTEGER DEFAULT 1"),
        ("findings", "project_id", "INTEGER DEFAULT 1"),
        ("findings", "asset_id", "INTEGER"),
        ("findings", "cvss_score", "FLOAT DEFAULT 0.0"),
        ("findings", "risk_score", "FLOAT DEFAULT 0.0"),
        ("findings", "endpoint", "VARCHAR(500) DEFAULT ''"),
        ("findings", "owner_id", "INTEGER"),
        ("findings", "due_date", "DATETIME"),
        ("findings", "first_seen", "DATETIME"),
        ("findings", "last_seen", "DATETIME"),
        ("findings", "resolved_at", "DATETIME"),
        ("releases", "organization_id", "INTEGER DEFAULT 1"),
    ]

    for table, col_name, col_def in migrations:
        if table in existing_tables:
            existing_cols = {c["name"] for c in inspector.get_columns(table)}
            if col_name not in existing_cols:
                try:
                    with db.engine.connect() as conn:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}"))
                        conn.commit()
                except Exception:
                    pass

    # Migrate or recreate audit_logs if schema has changed
    if "audit_logs" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("audit_logs")}
        if "action" not in existing_cols or "organization_id" not in existing_cols:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("DROP TABLE audit_logs"))
                    conn.commit()
                AuditLog.__table__.create(db.engine, checkfirst=True)
            except Exception:
                pass

    if "findings" in existing_tables:
        try:
            with db.engine.connect() as conn:
                conn.execute(text("""
                    UPDATE findings 
                    SET project_id = (SELECT project_id FROM scans WHERE scans.id = findings.scan_id)
                    WHERE (project_id IS NULL OR project_id = 1) AND scan_id IS NOT NULL
                """))
                conn.execute(text("""
                    UPDATE findings 
                    SET first_seen = created_at 
                    WHERE first_seen IS NULL AND created_at IS NOT NULL
                """))
                conn.execute(text("""
                    UPDATE findings 
                    SET last_seen = created_at 
                    WHERE last_seen IS NULL AND created_at IS NOT NULL
                """))
                conn.commit()
        except Exception:
            pass


def _seed_default_organization_and_user():
    """Ensure baseline enterprise organization and admin user exist."""
    # 1. Organization
    org = Organization.query.first()
    if not org:
        org = Organization(
            name="Default Security Organization",
            slug="default-org",
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(org)
        db.session.flush()

    # 2. Admin User
    admin = User.query.filter_by(email="admin@securegate.io").first()
    if not admin:
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw("Admin123!SecureGate".encode("utf-8"), salt).decode("utf-8")
        admin = User(
            email="admin@securegate.io",
            password_hash=hashed,
            full_name="Lead Security Architect",
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(admin)
        db.session.flush()

        membership = Membership(
            user_id=admin.id,
            organization_id=org.id,
            role="Owner",
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(membership)

    # 3. Default Organization Security Policy
    policy = SecurityPolicy.query.filter_by(organization_id=org.id, project_id=None).first()
    if not policy:
        policy = SecurityPolicy(
            organization_id=org.id,
            project_id=None,
            name="Organization Baseline Gate Policy",
            block_critical=True,
            block_high=True,
            block_medium=False,
            min_cvss_block=7.0,
            max_critical_allowed=0,
            max_high_allowed=0,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(policy)

    db.session.commit()


def _seed_default_settings():
    """Create default system settings if they don't exist."""
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
    org = Organization.query.first()
    org_id = org.id if org else 1

    if not Project.query.first():
        p = Project(
            organization_id=org_id,
            name="OWASP Juice Shop",
            target_url="http://localhost:3000",
            description="Default web application target for pre-release security gating.",
            environment="Development",
            is_demo=True
        )
        db.session.add(p)
        db.session.commit()

        try:
            from ..services.demo_data import seed_demo_data
            seed_demo_data()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 1. Multi-Tenancy & User Identity
# ---------------------------------------------------------------------------

class Organization(db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    slug = db.Column(db.String(150), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    memberships = db.relationship('Membership', backref='organization', lazy=True, cascade='all, delete-orphan')
    projects = db.relationship('Project', backref='organization', lazy=True, cascade='all, delete-orphan')
    policies = db.relationship('SecurityPolicy', backref='organization', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='organization', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'project_count': len(self.projects),
            'member_count': len(self.memberships),
        }


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(150), default='')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    memberships = db.relationship('Membership', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password: str):
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
        except Exception:
            return False

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Membership(db.Model):
    __tablename__ = 'memberships'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    role = db.Column(db.String(50), default='Developer')  # Owner, Admin, Security Engineer, Developer, Viewer
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'organization_id', name='uq_user_organization'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'organization_id': self.organization_id,
            'role': self.role,
            'user': self.user.to_dict() if self.user else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# 2. Projects & Asset Inventory
# ---------------------------------------------------------------------------

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    target_url = db.Column(db.String(500), nullable=False)
    environment = db.Column(db.String(50), default='Development')  # Development, Staging, Production
    repository_url = db.Column(db.String(500), default='')
    is_demo = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    scans = db.relationship('Scan', backref='project', lazy=True, cascade='all, delete-orphan')
    releases = db.relationship('Release', backref='project', lazy=True, cascade='all, delete-orphan')
    assets = db.relationship('Asset', backref='project', lazy=True, cascade='all, delete-orphan')
    canonical_findings = db.relationship('Finding', backref='project', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'name': self.name,
            'description': self.description,
            'target_url': self.target_url,
            'environment': self.environment,
            'repository_url': self.repository_url,
            'is_demo': self.is_demo,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'scan_count': len(self.scans),
            'asset_count': len(self.assets),
            'latest_scan': self.scans[-1].to_dict() if self.scans else None,
        }


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_type = db.Column(db.String(50), nullable=False, default='endpoint')  # domain, url, endpoint, api_endpoint, technology
    name = db.Column(db.String(500), nullable=False)
    url = db.Column(db.String(1000), default='')
    http_method = db.Column(db.String(20), default='GET')
    parameters = db.Column(db.Text, default='')
    technology = db.Column(db.String(200), default='')
    criticality = db.Column(db.String(20), default='Medium')  # Critical, High, Medium, Low
    status = db.Column(db.String(30), default='active')  # active, inactive, deprecated
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'project_id': self.project_id,
            'asset_type': self.asset_type,
            'name': self.name,
            'url': self.url,
            'http_method': self.http_method,
            'parameters': self.parameters,
            'technology': self.technology,
            'criticality': self.criticality,
            'status': self.status,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# 3. Scan Orchestration & Lifecycle Jobs
# ---------------------------------------------------------------------------

class ScanJob(db.Model):
    __tablename__ = 'scan_jobs'

    id = db.Column(db.Integer, primary_key=True)
    job_identifier = db.Column(db.String(100), unique=True, nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), default='baseline')  # baseline, spider, active, full
    status = db.Column(db.String(30), default='QUEUED', index=True)  # QUEUED, INITIALIZING, RUNNING, PROCESSING, COMPLETED, FAILED, CANCELLED, TIMEOUT
    progress = db.Column(db.Integer, default=0)
    stage_message = db.Column(db.String(255), default='Scan job queued')
    logs = db.Column(db.Text, default='')
    error_message = db.Column(db.Text, nullable=True)
    triggered_by = db.Column(db.String(100), default='manual')  # manual, scheduled, api, cicd
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'job_identifier': self.job_identifier,
            'organization_id': self.organization_id,
            'project_id': self.project_id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'progress': self.progress,
            'stage_message': self.stage_message,
            'logs': self.logs.split('\n') if self.logs else [],
            'error_message': self.error_message,
            'triggered_by': self.triggered_by,
            'scan_id': self.scan_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_identifier = db.Column(db.String(100), unique=True, nullable=False, index=True)
    target_url = db.Column(db.String(500), nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Integer, default=0)
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
            'organization_id': self.organization_id,
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


# ---------------------------------------------------------------------------
# 4. Canonical Vulnerabilities & Deduplication Lifecycle
# ---------------------------------------------------------------------------

class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(64), nullable=True, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True, index=True)
    name = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default='')
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low, Informational
    confidence = db.Column(db.String(20), default='Medium')  # High, Medium, Low, False Positive
    cvss_score = db.Column(db.Float, default=0.0)
    risk_score = db.Column(db.Float, default=0.0)
    cwe_id = db.Column(db.String(30), default='N/A')
    owasp_category = db.Column(db.String(100), default='Unmapped')
    owasp_year = db.Column(db.String(10), default='2021')
    url = db.Column(db.String(1000), default='')
    endpoint = db.Column(db.String(500), default='')
    method = db.Column(db.String(20), default='GET')
    parameter = db.Column(db.String(200), default='')
    evidence = db.Column(db.Text, default='')
    solution = db.Column(db.Text, default='')
    reference = db.Column(db.Text, default='')
    plugin_id = db.Column(db.String(50), default='')
    alert_ref = db.Column(db.String(50), default='')
    status = db.Column(db.String(30), default='open', index=True)  # open, confirmed, in_progress, resolved, accepted, false_positive, reopened
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    occurrences = db.relationship('FindingOccurrence', backref='finding', lazy=True, cascade='all, delete-orphan')
    risk_acceptance = db.relationship('RiskAcceptance', backref='finding', uselist=False, cascade='all, delete-orphan')
    false_positive_record = db.relationship('FalsePositive', backref='finding', uselist=False, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'fingerprint': self.fingerprint,
            'organization_id': self.organization_id,
            'project_id': self.project_id,
            'scan_id': self.scan_id,
            'asset_id': self.asset_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'cvss_score': self.cvss_score,
            'risk_score': round(self.risk_score, 1),
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'owasp_year': self.owasp_year,
            'url': self.url,
            'endpoint': self.endpoint or self.url,
            'method': self.method,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'solution': self.solution,
            'reference': self.reference,
            'plugin_id': self.plugin_id,
            'alert_ref': self.alert_ref,
            'status': self.status,
            'first_seen': self.first_seen.isoformat() if self.first_seen else (self.created_at.isoformat() if self.created_at else None),
            'last_seen': self.last_seen.isoformat() if self.last_seen else (self.created_at.isoformat() if self.created_at else None),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class FindingOccurrence(db.Model):
    __tablename__ = 'finding_occurrences'

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    url = db.Column(db.String(1000), default='')
    method = db.Column(db.String(20), default='GET')
    parameter = db.Column(db.String(200), default='')
    evidence = db.Column(db.Text, default='')
    attack_payload = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'scan_id': self.scan_id,
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'attack_payload': self.attack_payload,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# 5. Policies, Risk Acceptance & False Positives
# ---------------------------------------------------------------------------

class SecurityPolicy(db.Model):
    __tablename__ = 'security_policies'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=True, index=True)
    name = db.Column(db.String(150), default='Default Gate Policy')
    block_critical = db.Column(db.Boolean, default=True)
    block_high = db.Column(db.Boolean, default=True)
    block_medium = db.Column(db.Boolean, default=False)
    min_cvss_block = db.Column(db.Float, default=7.0)
    max_critical_allowed = db.Column(db.Integer, default=0)
    max_high_allowed = db.Column(db.Integer, default=0)
    require_production_authorization = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'project_id': self.project_id,
            'name': self.name,
            'block_critical': self.block_critical,
            'block_high': self.block_high,
            'block_medium': self.block_medium,
            'min_cvss_block': self.min_cvss_block,
            'max_critical_allowed': self.max_critical_allowed,
            'max_high_allowed': self.max_high_allowed,
            'require_production_authorization': self.require_production_authorization,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class RiskAcceptance(db.Model):
    __tablename__ = 'risk_acceptances'

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    justification = db.Column(db.Text, nullable=False)
    approved_by = db.Column(db.String(150), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='Active')  # Active, Expired, Revoked
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'organization_id': self.organization_id,
            'user_id': self.user_id,
            'justification': self.justification,
            'approved_by': self.approved_by,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class FalsePositive(db.Model):
    __tablename__ = 'false_positives'

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'organization_id': self.organization_id,
            'user_id': self.user_id,
            'reason': self.reason,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# 6. Immutable Audit Logging
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    user_email = db.Column(db.String(255), default='system')
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, default='{}')
    ip_address = db.Column(db.String(50), default='')
    user_agent = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        details_obj = {}
        try:
            details_obj = json.loads(self.details) if self.details else {}
        except Exception:
            details_obj = {'raw': self.details}

        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'user_id': self.user_id,
            'user_email': self.user_email,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': details_obj,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# 7. Releases & App Settings (Backwards Compatible)
# ---------------------------------------------------------------------------

class Release(db.Model):
    __tablename__ = 'releases'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, default=1, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    version = db.Column(db.String(50), default='')
    status = db.Column(db.String(20), nullable=False)  # PASS, REVIEW, BLOCK
    reason = db.Column(db.Text, default='')
    blocking_findings = db.Column(db.Integer, default=0)
    review_findings = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
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
