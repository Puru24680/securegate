"""
Demo Data Service
Seeds a realistic OWASP Juice Shop demo dataset with real-world ZAP findings,
historical scans, and release gate records. Labeled explicitly as Demo Project.
"""
from datetime import datetime, timezone, timedelta
from ..models.database import db, Project, Scan, Finding, Release, AppSettings
from ..security.severity_engine import enrich_finding, calculate_security_score, calculate_release_status


SAMPLE_JUICESHOP_FINDINGS = [
    {
        "name": "SQL Injection",
        "description": "SQL injection may be possible. The user-supplied input in the search query parameter is directly concatenated into a dynamic SQL command without parameterized sanitization. An attacker can manipulate backend queries, extract user password hashes, or bypass authentication.",
        "severity": "High",
        "confidence": "High",
        "url": "https://demo.owasp-juice.shop/rest/products/search",
        "method": "GET",
        "parameter": "q",
        "evidence": "q=apple')) UNION SELECT 1,id,email,password,4,5,6,7,8,9 FROM Users--",
        "solution": "Refactor database access to use parameterized prepared statements or an Object-Relational Mapper (ORM) with strict query binding. Never concatenate user-supplied input directly into SQL strings.",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        "cwe_id": "CWE-89",
        "plugin_id": "40018",
        "alert_ref": "40018-1",
    },
    {
        "name": "Cross Site Scripting (Reflected)",
        "description": "A reflected cross-site scripting (XSS) vulnerability was identified in the feedback submission endpoint. Malicious JavaScript injected via the comment parameter is echoed verbatim into the client DOM without HTML entity encoding.",
        "severity": "High",
        "confidence": "High",
        "url": "https://demo.owasp-juice.shop/api/Feedbacks",
        "method": "POST",
        "parameter": "comment",
        "evidence": "<iframe src=\"javascript:alert('XSS')\">",
        "solution": "Contextually encode all user-controlled data before rendering into HTML, JavaScript, CSS, or URL attributes. Implement a strict Content-Security-Policy (CSP).",
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "cwe_id": "CWE-79",
        "plugin_id": "40012",
        "alert_ref": "40012-1",
    },
    {
        "name": "Remote Code Execution (Template Injection)",
        "description": "Server-Side Template Injection (SSTI) allows remote attackers to evaluate arbitrary template expressions within the server runtime, potentially leading to arbitrary system command execution.",
        "severity": "Critical",
        "confidence": "Medium",
        "url": "https://demo.owasp-juice.shop/rest/basket/checkout",
        "method": "POST",
        "parameter": "coupon",
        "evidence": "#{7*7} => evaluated 49",
        "solution": "Do not pass untrusted user input directly into template engines. Use logic-less templates or execute templates within strict sandboxes.",
        "reference": "https://cwe.mitre.org/data/definitions/94.html",
        "cwe_id": "CWE-94",
        "plugin_id": "90019",
        "alert_ref": "90019-1",
    },
    {
        "name": "Anti-CSRF Tokens Check",
        "description": "No Anti-CSRF tokens were found in the state-changing HTML submission forms. Attackers can forge cross-origin POST requests on behalf of authenticated users.",
        "severity": "Medium",
        "confidence": "Medium",
        "url": "https://demo.owasp-juice.shop/profile",
        "method": "POST",
        "parameter": "username",
        "evidence": "<form action=\"/profile\" method=\"POST\"> without csrf token",
        "solution": "Implement cryptographically strong Synchronizer CSRF tokens or configure SameSite=Lax/Strict cookie attributes on session identifiers.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        "cwe_id": "CWE-352",
        "plugin_id": "10202",
        "alert_ref": "10202-1",
    },
    {
        "name": "Missing Anti-clickjacking Header (X-Frame-Options)",
        "description": "The HTTP response does not include the X-Frame-Options or Content-Security-Policy frame-ancestors header. The application can be framed in malicious third-party websites to trick users into unintentional interactions.",
        "severity": "Medium",
        "confidence": "High",
        "url": "https://demo.owasp-juice.shop/#/login",
        "method": "GET",
        "parameter": "",
        "evidence": "X-Frame-Options response header is missing",
        "solution": "Configure the web server to emit 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none';'.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "cwe_id": "CWE-1021",
        "plugin_id": "10020",
        "alert_ref": "10020-1",
    },
    {
        "name": "Cookie No HttpOnly Flag",
        "description": "A cookie has been set without the HttpOnly attribute. This permits client-side JavaScript scripts to access the cookie value, increasing risk of credential exfiltration via XSS.",
        "severity": "Low",
        "confidence": "High",
        "url": "https://demo.owasp-juice.shop/rest/user/authentication-details",
        "method": "GET",
        "parameter": "token",
        "evidence": "Set-Cookie: token=eyJhbGci...; Path=/; Secure",
        "solution": "Ensure that the HttpOnly flag is set on sensitive session and token cookies so they cannot be accessed by client-side script APIs.",
        "reference": "https://owasp.org/www-community/HttpOnly",
        "cwe_id": "CWE-1004",
        "plugin_id": "10010",
        "alert_ref": "10010-1",
    },
    {
        "name": "Server Leaks Information via 'X-Powered-By' HTTP Response Header",
        "description": "The web server response reveals internal runtime details via the 'X-Powered-By: Express' header. This assists threat actors in fingerprinting specific software versions.",
        "severity": "Low",
        "confidence": "High",
        "url": "https://demo.owasp-juice.shop/",
        "method": "GET",
        "parameter": "",
        "evidence": "X-Powered-By: Express",
        "solution": "Disable or strip the X-Powered-By header in Express middleware: app.disable('x-powered-by').",
        "reference": "https://expressjs.com/en/advanced/best-practice-security.html",
        "cwe_id": "CWE-200",
        "plugin_id": "10037",
        "alert_ref": "10037-1",
    },
    {
        "name": "Re-examine Cache-Control Directives",
        "description": "The response contains sensitive customer data but specifies non-restrictive cache controls. Shared proxies or browser caches could store sensitive responses.",
        "severity": "Informational",
        "confidence": "Medium",
        "url": "https://demo.owasp-juice.shop/rest/user/whoami",
        "method": "GET",
        "parameter": "",
        "evidence": "Cache-Control: public, max-age=14400",
        "solution": "Set 'Cache-Control: no-store, no-cache, must-revalidate, private' on authenticated user data endpoints.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
        "cwe_id": "CWE-525",
        "plugin_id": "10015",
        "alert_ref": "10015-1",
    }
]


def seed_demo_data(force: bool = False):
    """Seed demo project with scans, findings, and releases."""
    existing = Project.query.filter_by(is_demo=True).first()
    if existing and not force:
        return existing

    if existing and force:
        # Clear existing demo project
        db.session.delete(existing)
        db.session.commit()

    now = datetime.now(timezone.utc)
    settings = AppSettings.query.first()
    policy = settings.to_dict()['release_policy'] if settings else {}

    # 1. Create Demo Project
    demo_project = Project(
        name="OWASP Juice Shop (Demo Project)",
        description="Deliberately insecure modern web application for demonstrating SecureGate automated pre-release gating.",
        target_url="https://demo.owasp-juice.shop",
        is_demo=True,
        created_at=now - timedelta(days=7),
        updated_at=now
    )
    db.session.add(demo_project)
    db.session.flush()

    # 2. Historic Scan 1 (7 days ago) - Passed with low findings
    scan1 = Scan(
        project_id=demo_project.id,
        scan_identifier=f"ZAP-BASELINE-V141",
        target_url="https://demo.owasp-juice.shop",
        started_at=now - timedelta(days=7),
        completed_at=now - timedelta(days=7) + timedelta(seconds=24),
        duration=24,
        security_score=94.5,
        release_status="PASS",
        total_findings=2,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=1,
        informational_count=1,
        scanner="OWASP ZAP",
        created_at=now - timedelta(days=7)
    )
    db.session.add(scan1)
    db.session.flush()

    # Add 2 findings for Scan 1 (Historical passed scan: both fixed)
    f1_1 = Finding(
        scan_id=scan1.id,
        name="Server Leaks Information via 'X-Powered-By' HTTP Response Header",
        description="The web server response reveals internal runtime details via the 'X-Powered-By: Express' header.",
        severity="Low",
        confidence="High",
        url="https://demo.owasp-juice.shop/",
        method="GET",
        parameter="",
        evidence="X-Powered-By: Express",
        solution="Disable or strip the X-Powered-By header in Express middleware: app.disable('x-powered-by').",
        reference="https://expressjs.com/en/advanced/best-practice-security.html",
        cwe_id="CWE-200",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_year="2021",
        risk_score=20,
        plugin_id="10037",
        alert_ref="10037-1",
        status="fixed",
        created_at=now - timedelta(days=7)
    )
    f1_2 = Finding(
        scan_id=scan1.id,
        name="Re-examine Cache-Control Directives",
        description="Cache controls on non-sensitive assets.",
        severity="Informational",
        confidence="Medium",
        url="https://demo.owasp-juice.shop/assets/public.png",
        method="GET",
        parameter="",
        evidence="Cache-Control: public",
        solution="Verify static asset caching headers.",
        reference="https://owasp.org/",
        cwe_id="CWE-525",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_year="2021",
        risk_score=10,
        plugin_id="10015",
        alert_ref="10015-1",
        status="fixed",
        created_at=now - timedelta(days=7)
    )
    db.session.add_all([f1_1, f1_2])

    rel1 = Release(
        project_id=demo_project.id,
        scan_id=scan1.id,
        version="v1.0.0 (Release #141)",
        status="PASS",
        reason="Release passed. Only minor findings: 1 Low, 1 Informational.",
        blocking_findings=0,
        review_findings=0,
        created_at=now - timedelta(days=7)
    )
    db.session.add(rel1)

    # 3. Historic Scan 2 (3 days ago) - Review required (Medium findings)
    scan2 = Scan(
        project_id=demo_project.id,
        scan_identifier=f"ZAP-STAGING-V142",
        target_url="https://demo.owasp-juice.shop",
        started_at=now - timedelta(days=3),
        completed_at=now - timedelta(days=3) + timedelta(seconds=32),
        duration=32,
        security_score=86.0,
        release_status="REVIEW",
        total_findings=4,
        critical_count=0,
        high_count=0,
        medium_count=2,
        low_count=1,
        informational_count=1,
        scanner="OWASP ZAP",
        created_at=now - timedelta(days=3)
    )
    db.session.add(scan2)
    db.session.flush()

    # Add 4 findings for Scan 2 (Medium findings reviewed, low/info fixed)
    f2_1 = Finding(
        scan_id=scan2.id,
        name="Anti-CSRF Tokens Check",
        description="No Anti-CSRF tokens were found in the state-changing HTML submission forms.",
        severity="Medium",
        confidence="Medium",
        url="https://demo.owasp-juice.shop/profile",
        method="POST",
        parameter="username",
        evidence="<form action=\"/profile\" method=\"POST\"> without csrf token",
        solution="Implement synchronizer CSRF tokens or SameSite=Lax cookie attribute.",
        reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        cwe_id="CWE-352",
        owasp_category="A01:2021-Broken Access Control",
        owasp_year="2021",
        risk_score=50,
        plugin_id="10202",
        alert_ref="10202-1",
        status="reviewed",
        created_at=now - timedelta(days=3)
    )
    f2_2 = Finding(
        scan_id=scan2.id,
        name="Missing Anti-clickjacking Header (X-Frame-Options)",
        description="The HTTP response does not include the X-Frame-Options header.",
        severity="Medium",
        confidence="High",
        url="https://demo.owasp-juice.shop/#/login",
        method="GET",
        parameter="",
        evidence="X-Frame-Options response header is missing",
        solution="Configure web server to emit 'X-Frame-Options: DENY'.",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        cwe_id="CWE-1021",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_year="2021",
        risk_score=50,
        plugin_id="10020",
        alert_ref="10020-1",
        status="reviewed",
        created_at=now - timedelta(days=3)
    )
    f2_3 = Finding(
        scan_id=scan2.id,
        name="Server Leaks Information via 'X-Powered-By' HTTP Response Header",
        description="Runtime information disclosed in response header.",
        severity="Low",
        confidence="High",
        url="https://demo.owasp-juice.shop/",
        method="GET",
        parameter="",
        evidence="X-Powered-By: Express",
        solution="Disable X-Powered-By header.",
        reference="https://expressjs.com/",
        cwe_id="CWE-200",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_year="2021",
        risk_score=20,
        plugin_id="10037",
        alert_ref="10037-1",
        status="fixed",
        created_at=now - timedelta(days=3)
    )
    f2_4 = Finding(
        scan_id=scan2.id,
        name="Re-examine Cache-Control Directives",
        description="Cache controls on non-sensitive assets.",
        severity="Informational",
        confidence="Medium",
        url="https://demo.owasp-juice.shop/assets/theme.css",
        method="GET",
        parameter="",
        evidence="Cache-Control: public",
        solution="Verify static asset caching headers.",
        reference="https://owasp.org/",
        cwe_id="CWE-525",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_year="2021",
        risk_score=10,
        plugin_id="10015",
        alert_ref="10015-1",
        status="fixed",
        created_at=now - timedelta(days=3)
    )
    db.session.add_all([f2_1, f2_2, f2_3, f2_4])

    rel2 = Release(
        project_id=demo_project.id,
        scan_id=scan2.id,
        version="v1.1.0 (Release #142)",
        status="REVIEW",
        reason="Release requires review due to: 2 Medium severity findings.",
        blocking_findings=0,
        review_findings=2,
        created_at=now - timedelta(days=3)
    )
    db.session.add(rel2)

    # 4. Current Latest Scan (Blocked by Critical/High findings)
    enriched_findings = []
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for item in SAMPLE_JUICESHOP_FINDINGS:
        enriched = enrich_finding(item, policy)
        sev_counts[enriched['severity']] += 1
        enriched_findings.append(enriched)

    sec_score = calculate_security_score(enriched_findings)
    status, reason, blocking, review = calculate_release_status(enriched_findings, policy)

    scan3 = Scan(
        project_id=demo_project.id,
        scan_identifier="ZAP-RELEASE-CANDIDATE-V143",
        target_url="https://demo.owasp-juice.shop",
        started_at=now - timedelta(hours=2),
        completed_at=now - timedelta(hours=2) + timedelta(seconds=41),
        duration=41,
        security_score=sec_score,
        release_status=status,
        total_findings=len(enriched_findings),
        critical_count=sev_counts["Critical"],
        high_count=sev_counts["High"],
        medium_count=sev_counts["Medium"],
        low_count=sev_counts["Low"],
        informational_count=sev_counts["Informational"],
        scanner="OWASP ZAP",
        created_at=now - timedelta(hours=2)
    )
    db.session.add(scan3)
    db.session.flush()

    # Add findings for Scan 3 with realistic statuses:
    # Critical and High are 'open' (blocking release)
    # Medium are 'reviewed' (evaluated by security team)
    # Low / Informational are 'fixed' or 'open'
    for f in enriched_findings:
        f_status = 'open'
        if f['severity'] in ['Critical', 'High']:
            f_status = 'open'
        elif f['severity'] == 'Medium':
            f_status = 'reviewed'
        elif f['severity'] in ['Low', 'Informational']:
            f_status = 'fixed' if 'Cache' in f['name'] else 'open'

        f_model = Finding(
            scan_id=scan3.id,
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
            status=f_status,
            created_at=now - timedelta(hours=2)
        )
        db.session.add(f_model)

    # Release for Scan 3
    rel3 = Release(
        project_id=demo_project.id,
        scan_id=scan3.id,
        version="v1.2.0 (Release #143)",
        status=status,
        reason=reason,
        blocking_findings=blocking,
        review_findings=review,
        created_at=now - timedelta(hours=2)
    )
    db.session.add(rel3)

    db.session.commit()
    return demo_project
