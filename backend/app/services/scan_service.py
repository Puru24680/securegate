"""
Scan Service
Orchestrates report ingestion, finding normalization, vulnerability lifecycle deduplication,
asset inventory discovery, deterministic contextual risk scoring, and release gating.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from ..models.database import (
    db, Project, Scan, Finding, FindingOccurrence, Asset,
    Release, SecurityPolicy, AppSettings
)
from ..parsers.zap_parser import zap_parser
from ..security.severity_engine import (
    normalize_severity,
    calculate_security_score,
    calculate_release_status,
    calculate_contextual_risk_score,
    enrich_finding,
    SEVERITY_ORDER
)
from ..security.fingerprint import compute_finding_fingerprint, normalize_endpoint_path
from ..security.audit import AuditLogger


class ScanService:
    @staticmethod
    def process_zap_report(
        project_id: int,
        raw_report_data: Any,
        target_url: Optional[str] = None,
        scan_identifier: Optional[str] = None,
        triggered_by: str = "manual",
        user_id: Optional[int] = None,
        user_email: Optional[str] = None
    ) -> Scan:
        """
        Parses a ZAP JSON report, dedupes findings via SHA-256 fingerprints,
        updates vulnerability lifecycle states, discovers assets,
        calculates contextual risk scores, and evaluates security release policies.
        """
        now = datetime.now(timezone.utc)

        # Detect real target URL from the ZAP report itself
        detected_target = zap_parser.extract_target_url(raw_report_data)

        # Determine effective target URL
        if detected_target and str(detected_target).strip():
            resolved_url = str(detected_target).strip()
        elif target_url and str(target_url).strip() and str(target_url).strip() != "http://localhost:3000":
            resolved_url = str(target_url).strip()
        else:
            resolved_url = target_url or "http://localhost:3000"

        # Parse target details
        parsed_target = urlparse(resolved_url)
        target_hostname = parsed_target.netloc or parsed_target.path or resolved_url

        # Resolve or auto-register project based on detected target
        selected_project = db.session.get(Project, project_id) if project_id else None
        project = None

        if selected_project and selected_project.target_url == resolved_url:
            project = selected_project
        else:
            # Look for existing project matching this target URL
            project = Project.query.filter(Project.target_url == resolved_url).first()

            # If not found, look for existing project matching hostname
            if not project and parsed_target.netloc:
                for p in Project.query.all():
                    if p.target_url and urlparse(p.target_url).netloc == parsed_target.netloc:
                        project = p
                        break

            # If still not found and target differs from default Juice Shop demo URL, create new target project
            if not project:
                if resolved_url not in ("http://localhost:3000", "http://localhost:3000/"):
                    org_id = selected_project.organization_id if selected_project else 1
                    new_proj = Project(
                        organization_id=org_id,
                        name=target_hostname,
                        target_url=resolved_url,
                        description=f"Auto-registered target project from scan of {resolved_url}.",
                        environment="Development",
                        is_demo=False
                    )
                    db.session.add(new_proj)
                    db.session.commit()
                    project = new_proj
                else:
                    project = selected_project or Project.query.first()

        if not project:
            project = Project.query.first()
        if not project:
            project = Project(
                organization_id=1,
                name="OWASP Juice Shop",
                target_url=resolved_url,
                description="Default web application target for pre-release security gating.",
                environment="Development",
                is_demo=True
            )
            db.session.add(project)
            db.session.commit()

        # Parse alerts from raw ZAP JSON
        raw_findings = zap_parser.parse(raw_report_data)

        if not scan_identifier:
            scan_identifier = f"ZAP-{now.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # Retrieve applicable security policy
        policy_obj = (
            SecurityPolicy.query.filter_by(project_id=project.id).first()
            or SecurityPolicy.query.filter_by(organization_id=project.organization_id, project_id=None).first()
        )
        settings = AppSettings.query.first()
        policy_dict = settings.to_dict()['release_policy'] if settings else {
            'critical': 'BLOCK',
            'high': 'BLOCK',
            'medium': 'REVIEW',
            'low': 'PASS',
            'informational': 'PASS',
        }

        # 1. Discover or link Target Root Asset
        root_parsed = urlparse(resolved_url)
        root_name = root_parsed.path or "/"
        root_asset = Asset.query.filter_by(
            project_id=project.id,
            name=root_name,
            http_method="GET"
        ).first()
        if not root_asset:
            root_asset = Asset(
                organization_id=project.organization_id,
                project_id=project.id,
                asset_type="domain" if root_name == "/" else "endpoint",
                name=root_name,
                url=resolved_url,
                http_method="GET",
                criticality="High" if project.environment == "Production" else "Medium",
                last_seen=now
            )
            db.session.add(root_asset)
            db.session.flush()

        # 2. Enrich, fingerprint, and discover assets for each finding
        current_scan_fingerprints = set()
        active_findings_for_gate = []
        severity_counts = {s: 0 for s in SEVERITY_ORDER}

        # First create the Scan record
        scan = Scan(
            organization_id=project.organization_id,
            project_id=project.id,
            scan_identifier=scan_identifier,
            target_url=resolved_url,
            started_at=now,
            completed_at=now,
            duration=35,
            security_score=100.0,
            release_status="PENDING",
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            informational_count=0,
            scanner="OWASP ZAP",
            created_at=now
        )
        db.session.add(scan)
        db.session.flush()

        for rf in raw_findings:
            f_dict = {
                'name': rf.name,
                'description': rf.description,
                'severity': rf.severity,
                'confidence': rf.confidence,
                'url': rf.url or resolved_url,
                'method': rf.method or "GET",
                'parameter': rf.parameter or "",
                'evidence': rf.evidence or "",
                'solution': rf.solution or "",
                'reference': rf.reference or "",
                'cwe_id': rf.cwe_id or "N/A",
                'plugin_id': rf.plugin_id or "",
                'alert_ref': rf.alert_ref or "",
            }
            enriched = enrich_finding(f_dict, policy_dict)
            norm_severity = enriched['severity']

            # Auto-register Endpoint Asset
            endpoint_path = normalize_endpoint_path(enriched['url'])
            asset = Asset.query.filter_by(
                project_id=project.id,
                name=endpoint_path,
                http_method=enriched['method']
            ).first()
            if not asset:
                asset = Asset(
                    organization_id=project.organization_id,
                    project_id=project.id,
                    asset_type="api_endpoint" if "/api" in endpoint_path else "endpoint",
                    name=endpoint_path,
                    url=enriched['url'],
                    http_method=enriched['method'],
                    parameters=enriched['parameter'],
                    criticality="High" if project.environment == "Production" else "Medium",
                    first_seen=now,
                    last_seen=now
                )
                db.session.add(asset)
                db.session.flush()
            else:
                asset.last_seen = now

            # Compute canonical SHA-256 fingerprint
            fp = compute_finding_fingerprint(
                project_id=project.id,
                cwe_id=enriched['cwe_id'],
                url=enriched['url'],
                parameter=enriched['parameter'],
                plugin_id=enriched['plugin_id'],
                finding_name=enriched['name']
            )
            current_scan_fingerprints.add(fp)

            # Deduplication & Lifecycle check
            existing_finding = Finding.query.filter_by(
                project_id=project.id,
                fingerprint=fp
            ).first()

            if existing_finding:
                # Recurrence tracking
                rec_count = FindingOccurrence.query.filter_by(finding_id=existing_finding.id).count() + 1
                risk_score, priority, _ = calculate_contextual_risk_score(
                    severity=norm_severity,
                    confidence=enriched['confidence'],
                    cvss_score=existing_finding.cvss_score,
                    asset_criticality=asset.criticality,
                    environment=project.environment,
                    recurrence_count=rec_count
                )
                existing_finding.last_seen = now
                existing_finding.scan_id = scan.id
                existing_finding.asset_id = asset.id
                existing_finding.risk_score = risk_score
                existing_finding.severity = norm_severity
                existing_finding.evidence = enriched['evidence']

                # Lifecycle regression handling
                if existing_finding.status == 'resolved':
                    existing_finding.status = 'reopened'
                    existing_finding.resolved_at = None
                # Note: if existing_finding.status is 'accepted' or 'false_positive', we preserve it!

                finding_record = existing_finding
            else:
                # Brand new finding
                risk_score, priority, _ = calculate_contextual_risk_score(
                    severity=norm_severity,
                    confidence=enriched['confidence'],
                    cvss_score=0.0,
                    asset_criticality=asset.criticality,
                    environment=project.environment,
                    recurrence_count=1
                )
                finding_record = Finding(
                    fingerprint=fp,
                    organization_id=project.organization_id,
                    project_id=project.id,
                    scan_id=scan.id,
                    asset_id=asset.id,
                    name=enriched['name'],
                    description=enriched['description'],
                    severity=norm_severity,
                    confidence=enriched['confidence'],
                    cvss_score=0.0,
                    risk_score=risk_score,
                    cwe_id=enriched['cwe_id'],
                    owasp_category=enriched['owasp_category'],
                    owasp_year=enriched['owasp_year'],
                    url=enriched['url'],
                    endpoint=endpoint_path,
                    method=enriched['method'],
                    parameter=enriched['parameter'],
                    evidence=enriched['evidence'],
                    solution=enriched['solution'],
                    reference=enriched['reference'],
                    plugin_id=enriched['plugin_id'],
                    alert_ref=enriched['alert_ref'],
                    status='open',
                    first_seen=now,
                    last_seen=now,
                    created_at=now
                )
                db.session.add(finding_record)
                db.session.flush()

            # Record occurrence
            occurrence = FindingOccurrence(
                finding_id=finding_record.id,
                scan_id=scan.id,
                url=enriched['url'],
                method=enriched['method'],
                parameter=enriched['parameter'],
                evidence=enriched['evidence'],
                created_at=now
            )
            db.session.add(occurrence)

            severity_counts[norm_severity] = severity_counts.get(norm_severity, 0) + 1

            # Only count towards gating if not accepted and not false-positive
            if finding_record.status not in ('accepted', 'false_positive'):
                active_findings_for_gate.append({
                    'severity': norm_severity,
                    'name': finding_record.name,
                    'cvss_score': finding_record.cvss_score,
                    'risk_score': finding_record.risk_score
                })

        # 3. Mark previous findings for this target that were NOT seen in this scan as resolved
        earlier_active = Finding.query.filter(
            Finding.project_id == project.id,
            Finding.status.in_(['open', 'confirmed', 'in_progress', 'reopened'])
        ).all()

        for prev_f in earlier_active:
            if prev_f.fingerprint and prev_f.fingerprint not in current_scan_fingerprints:
                prev_host = urlparse(prev_f.url).netloc if prev_f.url else ''
                if not prev_host or not parsed_target.netloc or prev_host == parsed_target.netloc:
                    prev_f.status = 'resolved'
                    prev_f.resolved_at = now

        # 4. Calculate Scores and Evaluate Gate Decisions
        sec_score = calculate_security_score(active_findings_for_gate)
        status, reason, blocking_count, review_count = calculate_release_status(
            active_findings_for_gate, policy_dict
        )

        # Policy checks from SecurityPolicy model if present
        if policy_obj:
            crit_count = severity_counts.get('Critical', 0)
            high_count = severity_counts.get('High', 0)
            if policy_obj.block_critical and crit_count > policy_obj.max_critical_allowed:
                status = "BLOCK"
                reason = f"Security Policy violation: {crit_count} Critical vulnerabilities exceed max allowed ({policy_obj.max_critical_allowed})."
            elif policy_obj.block_high and high_count > policy_obj.max_high_allowed:
                status = "BLOCK"
                reason = f"Security Policy violation: {high_count} High vulnerabilities exceed max allowed ({policy_obj.max_high_allowed})."

        # Update Scan stats
        scan.security_score = sec_score
        scan.release_status = status
        scan.total_findings = len(current_scan_fingerprints)
        scan.critical_count = severity_counts.get('Critical', 0)
        scan.high_count = severity_counts.get('High', 0)
        scan.medium_count = severity_counts.get('Medium', 0)
        scan.low_count = severity_counts.get('Low', 0)
        scan.informational_count = severity_counts.get('Informational', 0)

        # 5. Create Release entry
        rel_count = Release.query.filter_by(project_id=project.id).count()
        release_ver = f"v1.{rel_count + 1}.0"
        release_entry = Release(
            organization_id=project.organization_id,
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

        project.updated_at = now
        db.session.commit()

        # 6. Immutable Audit Log
        AuditLogger.log(
            org_id=project.organization_id,
            action="scan.completed",
            resource_type="scan",
            resource_id=str(scan.id),
            user_id=user_id,
            user_email=user_email or "system",
            details={
                "project_id": project.id,
                "project_name": project.name,
                "target_url": resolved_url,
                "total_findings": scan.total_findings,
                "release_status": status,
                "security_score": sec_score,
                "triggered_by": triggered_by
            }
        )

        return scan

    @staticmethod
    def get_findings_filtered(
        project_id: Optional[int] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
        severity: Optional[str] = None,
        owasp_category: Optional[str] = None,
        cwe_id: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[Finding], int]:
        """Query canonical findings with rich filters, search, and pagination."""
        query = Finding.query

        if organization_id:
            query = query.filter(Finding.organization_id == organization_id)

        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        elif project_id:
            query = query.filter(Finding.project_id == project_id)

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
                (Finding.parameter.ilike(search_term)) |
                (Finding.endpoint.ilike(search_term))
            )

        total = query.count()
        findings = query.order_by(Finding.risk_score.desc(), Finding.id.asc()).offset((page - 1) * per_page).limit(per_page).all()
        return findings, total


scan_service = ScanService()
