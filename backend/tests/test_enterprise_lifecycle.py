"""
Unit & Integration Tests for Enterprise Vulnerability Lifecycle, Fingerprinting, and Governance
"""
import pytest
from datetime import datetime, timezone
from app.models.database import db, Project, Scan, Finding, FindingOccurrence, Asset, AuditLog, SecurityPolicy
from app.services.scan_service import scan_service
from app.security.fingerprint import compute_finding_fingerprint, normalize_endpoint_path
from app.security.severity_engine import calculate_contextual_risk_score


def test_fingerprint_normalization_and_determinism():
    # Dynamic IDs should normalize: /users/123/profile -> /users/{id}/profile
    p1 = normalize_endpoint_path("https://example.com/users/123/profile")
    p2 = normalize_endpoint_path("https://example.com/users/456/profile")
    assert p1 == p2 == "/users/{id}/profile"

    # Deterministic SHA-256 fingerprint
    fp1 = compute_finding_fingerprint(1, "89", "https://example.com/api/login", "username", "40018", "SQL Injection")
    fp2 = compute_finding_fingerprint(1, "89", "https://example.com/api/login", "username", "40018", "SQL Injection")
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string


def test_contextual_multi_factor_risk_scoring():
    # Production Critical Asset vs Development Low Asset
    score_prod, prio_prod, _ = calculate_contextual_risk_score(
        severity="High",
        confidence="High",
        cvss_score=8.2,
        asset_criticality="Critical",
        environment="Production",
        recurrence_count=3
    )

    score_dev, prio_dev, _ = calculate_contextual_risk_score(
        severity="High",
        confidence="High",
        cvss_score=8.2,
        asset_criticality="Low",
        environment="Development",
        recurrence_count=1
    )

    assert score_prod > score_dev
    assert "P0" in prio_prod or "P1" in prio_prod


def test_vulnerability_deduplication_and_lifecycle_flow(client, app):
    with app.app_context():
        # Setup test project
        project = Project(
            organization_id=1,
            name="Lifecycle Test App",
            target_url="http://localhost:3000",
            environment="Development"
        )
        db.session.add(project)
        db.session.commit()
        proj_id = project.id

        # Scan 1: Ingest report with XSS and SQLi
        scan1_report = {
            "site": [{
                "@name": "http://localhost:3000",
                "alerts": [
                    {
                        "alert": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "3",
                        "url": "http://localhost:3000/rest/user/login",
                        "param": "email",
                        "cweid": "89",
                        "desc": "SQL injection vulnerability"
                    },
                    {
                        "alert": "Cross Site Scripting",
                        "riskcode": "3",
                        "confidence": "3",
                        "url": "http://localhost:3000/search",
                        "param": "q",
                        "cweid": "79",
                        "desc": "Reflected XSS vulnerability"
                    }
                ]
            }]
        }

        scan1 = scan_service.process_zap_report(
            project_id=proj_id,
            raw_report_data=scan1_report,
            scan_identifier="SCAN-1"
        )
        assert scan1.release_status == "BLOCK"
        assert scan1.total_findings == 2

        findings_p1 = Finding.query.filter_by(project_id=proj_id).all()
        assert len(findings_p1) == 2
        sqli = next(f for f in findings_p1 if "SQL" in f.name)
        assert sqli.status == "open"
        assert sqli.fingerprint is not None

        # Verify Asset was automatically created in inventory
        assets = Asset.query.filter_by(project_id=proj_id).all()
        assert len(assets) >= 2

        # Step 2: Mark SQLi as False Positive via API
        fp_resp = client.post(f"/api/v1/findings/{sqli.id}/false-positive", json={
            "reason": "Input is parameterized through TypeORM and verified safe by AppSec team."
        })
        assert fp_resp.status_code == 200
        assert fp_resp.get_json()["finding"]["status"] == "false_positive"

        # Step 3: Scan 2: Run new scan with SAME findings
        # Verify: SQLi remains false_positive and does NOT re-block release gates!
        scan2 = scan_service.process_zap_report(
            project_id=proj_id,
            raw_report_data=scan1_report,
            scan_identifier="SCAN-2"
        )

        # Re-query findings: total count should still be 2 (Deduplicated!)
        findings_p2 = Finding.query.filter_by(project_id=proj_id).all()
        assert len(findings_p2) == 2

        sqli_after = db.session.get(Finding, sqli.id)
        assert sqli_after.status == "false_positive"  # Preserved!
        # Occurrence count should be 2
        assert len(sqli_after.occurrences) == 2

        # Step 4: Scan 3: Hardened scan without SQLi or XSS
        # Findings should be automatically marked 'resolved'
        scan3_report = {
            "site": [{
                "@name": "http://localhost:3000",
                "alerts": []
            }]
        }
        scan3 = scan_service.process_zap_report(
            project_id=proj_id,
            raw_report_data=scan3_report,
            scan_identifier="SCAN-3"
        )
        xss_finding = next(f for f in findings_p1 if "Cross Site" in f.name)
        xss_updated = db.session.get(Finding, xss_finding.id)
        assert xss_updated.status == "resolved"
        assert xss_updated.resolved_at is not None

        # Verify Audit Logs were written
        audit_records = AuditLog.query.filter_by(organization_id=1).all()
        assert len(audit_records) > 0
