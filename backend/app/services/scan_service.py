"""
Scan Service
Orchestrates report ingestion, finding normalization, risk evaluation, and release gating.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from ..models.database import db, Project, Scan, Finding, Release, AppSettings
from ..parsers.zap_parser import zap_parser
from ..security.severity_engine import (
    normalize_severity,
    calculate_security_score,
    calculate_release_status,
    enrich_finding,
    SEVERITY_ORDER
)


class ScanService:
    @staticmethod
    def process_zap_report(
        project_id: int,
        raw_report_data: Any,
        target_url: Optional[str] = None,
        scan_identifier: Optional[str] = None
    ) -> Scan:
        """
        Parses a ZAP JSON report, enriches findings, stores models,
        calculates security score and evaluates the release gate.
        """
        project = db.session.get(Project, project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} not found.")

        # Parse alerts from ZAP JSON
        raw_findings = zap_parser.parse(raw_report_data)

        # Retrieve current release policy
        settings = AppSettings.query.first()
        policy = settings.to_dict()['release_policy'] if settings else {
            'critical': 'BLOCK',
            'high': 'BLOCK',
            'medium': 'REVIEW',
            'low': 'PASS',
            'informational': 'PASS',
        }

        # Determine effective target URL
        resolved_url = target_url or project.target_url or "https://demo.owasp-juice.shop"
        if not scan_identifier:
            scan_identifier = f"ZAP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # Enrich and build finding records
        findings_to_create = []
        severity_counts = {s: 0 for s in SEVERITY_ORDER}

        for rf in raw_findings:
            f_dict = {
                'name': rf.name,
                'description': rf.description,
                'severity': rf.severity,
                'confidence': rf.confidence,
                'url': rf.url or resolved_url,
                'method': rf.method,
                'parameter': rf.parameter,
                'evidence': rf.evidence,
                'solution': rf.solution,
                'reference': rf.reference,
                'cwe_id': rf.cwe_id,
                'plugin_id': rf.plugin_id,
                'alert_ref': rf.alert_ref,
            }
            enriched = enrich_finding(f_dict, policy)
            severity = enriched['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            findings_to_create.append(enriched)

        # Calculate scores and release decision
        sec_score = calculate_security_score(findings_to_create)
        status, reason, blocking_count, review_count = calculate_release_status(findings_to_create, policy)

        # Create Scan record
        now = datetime.now(timezone.utc)
        scan = Scan(
            project_id=project.id,
            scan_identifier=scan_identifier,
            target_url=resolved_url,
            started_at=now,
            completed_at=now,
            duration=35, # standard baseline duration in seconds
            security_score=sec_score,
            release_status=status,
            total_findings=len(findings_to_create),
            critical_count=severity_counts.get('Critical', 0),
            high_count=severity_counts.get('High', 0),
            medium_count=severity_counts.get('Medium', 0),
            low_count=severity_counts.get('Low', 0),
            informational_count=severity_counts.get('Informational', 0),
            scanner="OWASP ZAP",
            created_at=now
        )
        db.session.add(scan)
        db.session.flush() # obtain scan.id

        # Attach findings to scan
        current_finding_names = set()
        for f in findings_to_create:
            current_finding_names.add(f['name'])
            finding_model = Finding(
                scan_id=scan.id,
                name=f['name'],
                description=f['description'],
                severity=f['severity'],
                confidence=f['confidence'],
                url=f['url'],
                method=f['method'],
                parameter=f['parameter'],
                evidence=f['evidence'],
                solution=f['solution'],
                reference=f['reference'],
                cwe_id=f['cwe_id'],
                owasp_category=f['owasp_category'],
                owasp_year=f['owasp_year'],
                risk_score=f['risk_score'],
                plugin_id=f['plugin_id'],
                alert_ref=f['alert_ref'],
                status='open',
                created_at=now
            )
            db.session.add(finding_model)

        # In pre-release gating: if an earlier open finding is no longer detected in this new scan, mark it fixed
        earlier_open_findings = Finding.query.join(Scan).filter(
            Scan.project_id == project.id,
            Finding.scan_id != scan.id,
            Finding.status == 'open'
        ).all()
        for prev_f in earlier_open_findings:
            if prev_f.name not in current_finding_names:
                prev_f.status = 'fixed'

        # Create Release entry
        rel_count = Release.query.filter_by(project_id=project.id).count()
        release_ver = f"v1.{rel_count + 1}.0"
        release_entry = Release(
            project_id=project.id,
            scan_id=scan.id,
            version=release_ver,
            status=status,
            reason=reason,
            blocking_findings=blocking_count,
            review_findings=review_count,
            created_at=now
        )
        db.session.add(release_entry)

        # Commit all changes
        project.updated_at = now
        db.session.commit()

        return scan

    @staticmethod
    def get_findings_filtered(
        project_id: Optional[int] = None,
        scan_id: Optional[int] = None,
        severity: Optional[str] = None,
        owasp_category: Optional[str] = None,
        cwe_id: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[Finding], int]:
        """Query findings with rich filters, search, and pagination."""
        query = Finding.query

        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        elif project_id:
            query = query.join(Scan).filter(Scan.project_id == project_id)

        if severity and severity.lower() != 'all':
            query = query.filter(Finding.severity == normalize_severity(severity))

        if owasp_category and owasp_category.lower() != 'all':
            query = query.filter(Finding.owasp_category.ilike(f"%{owasp_category}%"))

        if cwe_id and cwe_id.lower() != 'all':
            query = query.filter(Finding.cwe_id.ilike(f"%{cwe_id}%"))

        if status and status.lower() != 'all':
            query = query.filter(Finding.status == status)

        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (Finding.name.ilike(search_term)) |
                (Finding.description.ilike(search_term)) |
                (Finding.url.ilike(search_term)) |
                (Finding.parameter.ilike(search_term))
            )

        # Order by severity priority, then risk score descending
        # Critical, High, Medium, Low, Informational
        total = query.count()
        findings = query.order_by(Finding.risk_score.desc(), Finding.id.asc()).offset((page - 1) * per_page).limit(per_page).all()
        return findings, total


scan_service = ScanService()
