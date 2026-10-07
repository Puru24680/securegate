"""
Report Service
Generates structured security assessment reports and print-friendly HTML/PDF views.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from ..models.database import db, Scan, Finding, Project, AppSettings
from ..security.severity_engine import SEVERITY_ORDER


class ReportService:
    @staticmethod
    def generate_report_data(scan_id: int) -> Dict[str, Any]:
        """Generate comprehensive structured data for a scan security report."""
        scan = db.session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan #{scan_id} not found.")

        project = db.session.get(Project, scan.project_id)
        findings = Finding.query.filter_by(scan_id=scan.id).all()
        settings = AppSettings.query.first()
        policy = settings.to_dict()['release_policy'] if settings else {}

        # Distribution calculation
        distribution = {s: 0 for s in SEVERITY_ORDER}
        owasp_coverage: Dict[str, int] = {}
        cwe_coverage: Dict[str, int] = {}

        for f in findings:
            distribution[f.severity] = distribution.get(f.severity, 0) + 1
            cat = f.owasp_category or "Unmapped"
            owasp_coverage[cat] = owasp_coverage.get(cat, 0) + 1
            if f.cwe_id and f.cwe_id != "N/A":
                cwe_coverage[f.cwe_id] = cwe_coverage.get(f.cwe_id, 0) + 1

        # Categorized lists
        findings_by_severity = {
            s: [f.to_dict() for f in findings if f.severity == s]
            for s in SEVERITY_ORDER
        }

        # Executive summary logic
        total = len(findings)
        score = scan.security_score
        status = scan.release_status

        if status == 'BLOCK':
            summary_statement = (
                f"The automated security evaluation for {project.name if project else 'the target'} has resulted in a BLOCKED release decision. "
                f"A total of {scan.critical_count} Critical and {scan.high_count} High severity vulnerabilities were detected, "
                f"exceeding the strict security gate policy threshold. Immediate remediation is required before deployment to production."
            )
        elif status == 'REVIEW':
            summary_statement = (
                f"The automated security evaluation for {project.name if project else 'the target'} concluded with a REVIEW status. "
                f"While no blocking Critical or High vulnerabilities were detected, {scan.medium_count} Medium severity findings "
                f"require manual sign-off by the Application Security or DevSecOps lead before promotion."
            )
        else:
            summary_statement = (
                f"The automated security evaluation for {project.name if project else 'the target'} has PASSED all release gating gates. "
                f"With a Security Posture Score of {score}/100 and no high-risk security flaws identified, "
                f"the application artifact meets compliance and production safety baselines."
            )

        # Strategic recommendations built dynamically from actual findings in the scan
        recommendations = []
        seen_rec_names = set()

        # Prioritize Critical & High findings
        for f in findings:
            if f.severity in ('Critical', 'High') and f.name not in seen_rec_names:
                seen_rec_names.add(f.name)
                details = f.solution if f.solution else (
                    f"Remediate {f.name} on affected endpoint {f.url}. Implement input validation, parameterized queries, and defensive access controls."
                )
                cat_label = f"{f.owasp_category} / {f.cwe_id}" if f.cwe_id != "N/A" else f.owasp_category
                recommendations.append({
                    "priority": "P0 - Immediate Blocker",
                    "focus": f"Remediate {f.name} ({cat_label})",
                    "details": details
                })
                if len(recommendations) >= 4:
                    break

        # Then Medium findings
        if len(recommendations) < 4:
            for f in findings:
                if f.severity == 'Medium' and f.name not in seen_rec_names:
                    seen_rec_names.add(f.name)
                    details = f.solution if f.solution else (
                        f"Review and harden configurations for {f.name} on endpoint {f.url}."
                    )
                    cat_label = f.cwe_id if f.cwe_id != "N/A" else f.owasp_category
                    recommendations.append({
                        "priority": "P1 - Pre-Release Review",
                        "focus": f"Harden {f.name} ({cat_label})",
                        "details": details
                    })
                    if len(recommendations) >= 4:
                        break

        # Then Low / Informational findings
        if len(recommendations) < 3:
            for f in findings:
                if f.severity in ('Low', 'Informational') and f.name not in seen_rec_names:
                    seen_rec_names.add(f.name)
                    details = f.solution if f.solution else (
                        f"Address {f.name} as part of continuous security maintenance."
                    )
                    recommendations.append({
                        "priority": "P2 - Continuous Hygiene",
                        "focus": f"Mitigate {f.name}",
                        "details": details
                    })
                    if len(recommendations) >= 3:
                        break

        # If zero findings detected:
        if not recommendations:
            recommendations.append({
                "priority": "Verified Baseline",
                "focus": "Zero Security Vulnerabilities Detected",
                "details": "The target web application artifact has passed all automated pre-release security gating criteria with no actionable flaws detected."
            })

        return {
            "title": "SecureGate Automated Pre-Release Security Assessment",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan.id,
            "scan_identifier": scan.scan_identifier,
            "application_name": project.name if project else "Target Application",
            "target_url": scan.target_url,
            "scanner": scan.scanner,
            "security_score": scan.security_score,
            "release_status": scan.release_status,
            "executive_summary": summary_statement,
            "release_policy_applied": policy,
            "metrics": {
                "total_findings": total,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "informational": scan.informational_count,
            },
            "severity_distribution": distribution,
            "owasp_coverage": owasp_coverage,
            "cwe_coverage": cwe_coverage,
            "findings_by_severity": findings_by_severity,
            "strategic_recommendations": recommendations,
        }

    @staticmethod
    def generate_html_report(scan_id: int) -> str:
        """Generates print-ready HTML for export and PDF generation."""
        report = ReportService.generate_report_data(scan_id)
        metrics = report['metrics']
        status = report['release_status']
        status_color = "#ef4444" if status == "BLOCK" else ("#f59e0b" if status == "REVIEW" else "#10b981")

        findings_html = ""
        for sev in SEVERITY_ORDER:
            flist = report['findings_by_severity'].get(sev, [])
            if not flist:
                continue
            findings_html += f"""
            <div class="severity-section">
                <h3 class="sev-heading sev-{sev.lower()}">{sev} Vulnerabilities ({len(flist)})</h3>
            """
            for f in flist:
                findings_html += f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="finding-title">{f['name']}</span>
                        <span class="badge badge-{f['severity'].lower()}">{f['severity']}</span>
                    </div>
                    <div class="finding-meta">
                        <span><strong>OWASP:</strong> {f['owasp_category']}</span> &bull; 
                        <span><strong>CWE:</strong> {f['cwe_id']}</span> &bull; 
                        <span><strong>Endpoint:</strong> <code>{f['method']} {f['url']}</code></span>
                        {f" &bull; <span><strong>Parameter:</strong> <code>{f['parameter']}</code></span>" if f['parameter'] else ""}
                    </div>
                    <p class="finding-desc">{f['description'][:350]}{'...' if len(f['description']) > 350 else ''}</p>
                    {f"<div class='evidence-box'><strong>Evidence:</strong> <code>{f['evidence']}</code></div>" if f['evidence'] else ""}
                    {f"<div class='solution-box'><strong>Remediation:</strong> {f['solution']}</div>" if f['solution'] else ""}
                </div>
                """
            findings_html += "</div>"

        if not findings_html:
            findings_html = """
            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 24px; text-align: center; color: #166534; margin: 12px 0;">
                <strong style="font-size: 15px; display: block; margin-bottom: 4px;">Zero Security Flaws Detected</strong>
                <span style="font-size: 13px; color: #15803d;">All pre-release security gating criteria satisfied. Artifact meets production compliance standards.</span>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureGate Security Assessment - {report['application_name']}</title>
<style>
  @page {{ size: A4; margin: 18mm; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.5;
    background: #ffffff;
    margin: 0;
    padding: 24px;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2px solid #0f172a;
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .logo {{
    font-size: 24px;
    font-weight: 800;
    letter-spacing: -0.05em;
    color: #0f172a;
  }}
  .logo span {{ color: #3b82f6; }}
  .tagline {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; }}
  .score-badge {{
    text-align: right;
  }}
  .status-pill {{
    display: inline-block;
    padding: 6px 14px;
    border-radius: 9999px;
    font-size: 13px;
    font-weight: 700;
    color: #ffffff;
    background-color: {status_color};
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .score-number {{
    font-size: 28px;
    font-weight: 800;
    color: #0f172a;
    margin-top: 4px;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }}
  .metric-card {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px 16px;
  }}
  .metric-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 600; }}
  .metric-val {{ font-size: 20px; font-weight: 700; color: #0f172a; margin-top: 4px; }}
  .section {{
    margin-bottom: 28px;
  }}
  .section-title {{
    font-size: 16px;
    font-weight: 700;
    color: #0f172a;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 6px;
    margin-bottom: 12px;
  }}
  .summary-text {{
    font-size: 14px;
    color: #334155;
    background: #f1f5f9;
    padding: 14px 18px;
    border-radius: 8px;
    border-left: 4px solid {status_color};
  }}
  .finding-card {{
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 12px;
    background: #ffffff;
    page-break-inside: avoid;
  }}
  .finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
  }}
  .finding-title {{ font-size: 14px; font-weight: 700; color: #0f172a; }}
  .finding-meta {{ font-size: 12px; color: #64748b; margin-bottom: 8px; }}
  .finding-desc {{ font-size: 12px; color: #475569; margin: 6px 0; }}
  .evidence-box, .solution-box {{
    font-size: 11px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    padding: 8px 10px;
    margin-top: 6px;
  }}
  .solution-box {{ background: #f0fdf4; border-color: #bbf7d0; color: #166534; }}
  .badge {{
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
  }}
  .badge-critical {{ background: #fee2e2; color: #991b1b; }}
  .badge-high {{ background: #ffedd5; color: #9a3412; }}
  .badge-medium {{ background: #fef3c7; color: #92400e; }}
  .badge-low {{ background: #e0f2fe; color: #075985; }}
  .badge-informational {{ background: #f1f5f9; color: #475569; }}
  .sev-critical {{ color: #b91c1c; }}
  .sev-high {{ color: #c2410c; }}
  .sev-medium {{ color: #b45309; }}
  .sev-low {{ color: #0369a1; }}
  .sev-informational {{ color: #475569; }}
  .actions-list {{ font-size: 13px; color: #334155; padding-left: 20px; }}
  .actions-list li {{ margin-bottom: 8px; }}
  .print-btn {{
    background: #0f172a;
    color: white;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    margin-bottom: 20px;
  }}
  @media print {{
    .print-btn {{ display: none; }}
    body {{ padding: 0; }}
  }}
</style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>

  <div class="header">
    <div>
      <div class="logo">SECURE<span>GATE</span></div>
      <div class="tagline">Automated Pre-Release Security Gate Assessment</div>
      <div style="font-size: 12px; color: #64748b; margin-top: 6px;">
        <strong>Application:</strong> {report['application_name']} &bull;
        <strong>Target:</strong> {report['target_url']} &bull;
        <strong>Scan:</strong> {report['scan_identifier']} &bull;
        <strong>Date:</strong> {report['generated_at'][:10]}
      </div>
    </div>
    <div class="score-badge">
      <div class="status-pill">{status}</div>
      <div class="score-number">{report['security_score']} <span style="font-size: 14px; font-weight: 500; color: #64748b;">/ 100</span></div>
    </div>
  </div>

  <div class="grid">
    <div class="metric-card">
      <div class="metric-label">Critical Risks</div>
      <div class="metric-val" style="color: #ef4444;">{metrics['critical']}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">High Risks</div>
      <div class="metric-val" style="color: #f97316;">{metrics['high']}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Medium Risks</div>
      <div class="metric-val" style="color: #f59e0b;">{metrics['medium']}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Total Findings</div>
      <div class="metric-val">{metrics['total_findings']}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-text">{report['executive_summary']}</div>
  </div>

  <div class="section">
    <div class="section-title">Strategic Remediation Guidance</div>
    <ul class="actions-list">
      {"".join([f"<li><strong>{r['priority']} - {r['focus']}:</strong> {r['details']}</li>" for r in report['strategic_recommendations']])}
    </ul>
  </div>

  <div class="section">
    <div class="section-title">Detailed Vulnerability Registry</div>
    {findings_html}
  </div>

  <div style="margin-top: 32px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; text-align: center;">
    Generated automatically by SecureGate Enterprise Security Decision Platform &bull; OWASP ZAP Ingestion Engine
  </div>
</body>
</html>"""
        return html_template


report_service = ReportService()
