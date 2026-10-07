"""
Tests for OWASP ZAP JSON Parser
"""
import pytest
from app.parsers.zap_parser import zap_parser


def test_parse_valid_zap_standard_format():
    sample_zap = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://localhost:3000",
                "@host": "localhost",
                "@port": "3000",
                "alerts": [
                    {
                        "pluginId": "40018",
                        "alertRef": "40018-1",
                        "alert": "SQL Injection",
                        "name": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "3",
                        "riskdesc": "High (High)",
                        "desc": "SQL injection may be possible.",
                        "instances": [
                            {
                                "uri": "http://localhost:3000/rest/products/search",
                                "method": "GET",
                                "param": "q",
                                "attack": "' OR '1'='1",
                                "evidence": "syntax error near unexpected token"
                            }
                        ],
                        "solution": "Use parameterized queries.",
                        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "cweid": "89"
                    }
                ]
            }
        ]
    }

    findings = zap_parser.parse(sample_zap)
    assert len(findings) == 1
    f = findings[0]
    assert f.name == "SQL Injection"
    assert f.severity == "High"
    assert f.confidence == "High"
    assert f.url == "http://localhost:3000/rest/products/search"
    assert f.method == "GET"
    assert f.parameter == "q"
    assert f.evidence == "syntax error near unexpected token"
    assert f.cwe_id == "CWE-89"


def test_parse_malformed_json_string():
    with pytest.raises(ValueError, match="Invalid JSON"):
        zap_parser.parse("{{malformed: json, not valid}")


def test_parse_empty_findings():
    empty_zap = {"site": [{"alerts": []}]}
    findings = zap_parser.parse(empty_zap)
    assert len(findings) == 0


def test_parse_missing_fields_gracefully():
    sparse_zap = {
        "alerts": [
            {
                "alert": "Incomplete Warning",
                # all other fields missing
            }
        ]
    }
    findings = zap_parser.parse(sparse_zap)
    assert len(findings) == 1
    f = findings[0]
    assert f.name == "Incomplete Warning"
    assert f.severity == "Low"  # default
    assert f.confidence == "Medium"  # default
    assert f.url == ""
    assert f.cwe_id == "N/A"


def test_deduplication():
    duplicate_zap = {
        "alerts": [
            {
                "alert": "Directory Browsing",
                "url": "http://localhost:3000/assets/",
                "param": "",
                "riskcode": "2"
            },
            {
                "alert": "Directory Browsing",
                "url": "http://localhost:3000/assets/",
                "param": "",
                "riskcode": "2"
            }
        ]
    }
    findings = zap_parser.parse(duplicate_zap)
    assert len(findings) == 1


def test_parse_xml_to_json_structure():
    xml_json = {
        "OWASPZAPReport": {
            "site": {
                "@name": "https://testphp.vulnweb.com",
                "alerts": {
                    "alertitem": [
                        {
                            "alert": "Cross Site Scripting",
                            "riskcode": "3",
                            "cweid": "79",
                            "url": "https://testphp.vulnweb.com/search.php"
                        }
                    ]
                }
            }
        }
    }
    findings = zap_parser.parse(xml_json)
    assert len(findings) == 1
    assert findings[0].name == "Cross Site Scripting"
    assert findings[0].severity == "High"
    assert findings[0].cwe_id == "CWE-79"
    target = zap_parser.extract_target_url(xml_json)
    assert target == "https://testphp.vulnweb.com"


def test_parse_generic_vulnerabilities_array():
    generic = {
        "target": "https://example.com",
        "vulnerabilities": [
            {
                "title": "SQL Injection",
                "severity": "CRITICAL",
                "url": "https://example.com/api",
                "cwe_id": "89"
            }
        ]
    }
    findings = zap_parser.parse(generic)
    assert len(findings) == 1
    assert findings[0].name == "SQL Injection"
    assert findings[0].severity == "Critical"


def test_parse_flat_list_of_alerts():
    flat_list = [
        {
            "alert": "Remote Code Execution",
            "risk": "High",
            "url": "https://custom.app/cmd"
        }
    ]
    findings = zap_parser.parse(flat_list)
    assert len(findings) == 1
    assert findings[0].name == "Remote Code Execution"
    assert findings[0].severity == "High"


def test_zap_riskdesc_confidence_separation():
    """Ensure confidence in riskdesc (e.g. 'Informational (Medium)') does not elevate severity."""
    zap_report = {
        "site": [
            {
                "@name": "https://my-custom-target.com",
                "alerts": [
                    {
                        "alert": "Content-Cache Directives",
                        "riskcode": "0",
                        "riskdesc": "Informational (Medium)",
                        "confidence": "2",
                        "url": "https://my-custom-target.com/assets"
                    },
                    {
                        "alert": "Cookie No HttpOnly Flag",
                        "riskcode": "1",
                        "riskdesc": "Low (High)",
                        "confidence": "3",
                        "url": "https://my-custom-target.com/login"
                    },
                    {
                        "alert": "Missing Anti-clickjacking Header",
                        "riskcode": "2",
                        "riskdesc": "Medium (High)",
                        "confidence": "3",
                        "url": "https://my-custom-target.com/page"
                    }
                ]
            }
        ]
    }
    findings = zap_parser.parse(zap_report)
    assert len(findings) == 3
    assert findings[0].name == "Content-Cache Directives"
    assert findings[0].severity == "Informational"  # NOT Medium
    assert findings[0].confidence == "Medium"

    assert findings[1].name == "Cookie No HttpOnly Flag"
    assert findings[1].severity == "Low"  # NOT High
    assert findings[1].confidence == "High"

    assert findings[2].name == "Missing Anti-clickjacking Header"
    assert findings[2].severity == "Medium"  # NOT High
    assert findings[2].confidence == "High"


def test_extract_target_url_flat_list():
    """Ensure flat list of alerts extracts the host correctly without UnboundLocalError."""
    flat_list = [
        {
            "alert": "SQL Injection",
            "risk": "High",
            "url": "https://secure-target.net/search?id=1"
        }
    ]
    target = zap_parser.extract_target_url(flat_list)
    assert target == "https://secure-target.net"


def test_parse_zap_automation_framework_logfile():
    """Ensure ZAP execution logs with site: null are parsed into findings and target URL is detected."""
    zap_af_report = {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "site": None,
        "domains": [],
        "logFile": (
            "2026-10-07 12:08:49,441 [ZAP-QuickStart-AttackThread] INFO  AttackThread - Attacking https://pentest-ground.com:4280\r\n"
            "2026-10-07 12:09:05,776 [ZAP-ActiveScanner-6] WARN  PathTraversalScanRule - An error occurred while checking [GET] [https://pentest-ground.com:4280/vulnerabilities/open_redirect/source/low.php?redirect=info.php?id=2], parameter [redirect] for Path Traversal.\r\n"
            "2026-10-07 12:09:18,985 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin https://pentest-ground.com:4280 | PathTraversalScanRule in 21.682s with 533 message(s) sent and 1 alert(s) raised.\r\n"
            "2026-10-07 12:09:40,119 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin https://pentest-ground.com:4280 | RemoteFileIncludeScanRule in 21.133s with 351 message(s) sent and 1 alert(s) raised.\r\n"
            "2026-10-07 12:10:16,946 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin https://pentest-ground.com:4280 | ExternalRedirectScanRule in 36.825s with 317 message(s) sent and 1 alert(s) raised.\r\n"
            "2026-10-07 12:10:36,865 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin https://pentest-ground.com:4280 | CrossSiteScriptingScanRule in 10.003s with 190 message(s) sent and 2 alert(s) raised.\r\n"
            "2026-10-07 12:11:22,111 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin https://pentest-ground.com:4280 | SqlInjectionScanRule in 45.246s with 672 message(s) sent and 11 alert(s) raised.\r\n"
            "2026-10-07 12:12:05,059 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin https://pentest-ground.com:4280 | CommandInjectionScanRule in 42.946s with 667 message(s) sent and 1 alert(s) raised.\r\n"
            "2026-10-07 12:14:13,981 [ZAP-Scanner-0] INFO  HostProcess - completed host https://pentest-ground.com:4280 in 324.527s with 17 alert(s) raised."
        )
    }

    target = zap_parser.extract_target_url(zap_af_report)
    assert target == "https://pentest-ground.com:4280"

    findings = zap_parser.parse(zap_af_report)
    assert len(findings) == 17

    # Check rule breakdown
    severities = [f.severity for f in findings]
    assert severities.count("Critical") == 1  # Command Injection
    assert severities.count("High") == 15      # 11 SQLi + 2 XSS + 1 Path Traversal + 1 RFI
    assert severities.count("Medium") == 1    # 1 Open Redirect


def test_parse_sarif_format():
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "js/sql-injection",
                                "name": "SQL Injection in JavaScript",
                                "shortDescription": {"text": "Database query built from user-controlled sources"},
                                "properties": {"tags": ["cwe-089"]}
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "js/sql-injection",
                        "level": "error",
                        "message": {"text": "Query built from untrusted input without parameterization."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://api.example.com/users/search.js"}
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    findings = zap_parser.parse(sarif_data)
    assert len(findings) == 1
    assert findings[0].name == "Database query built from user-controlled sources"
    assert findings[0].severity in ("High", "Critical")
    assert findings[0].cwe_id == "CWE-089"
    assert findings[0].url == "https://api.example.com/users/search.js"


def test_parse_generic_vulnerabilities_format():
    generic_data = {
        "target": "https://production-app.io",
        "vulnerabilities": [
            {
                "title": "Cross-Site Scripting (Stored)",
                "risk": "High",
                "cwe": "79",
                "url": "https://production-app.io/profile",
                "param": "bio",
                "remediation": "Encode all HTML output contextually."
            },
            {
                "title": "Hardcoded Secret Key",
                "severity": "Critical",
                "cwe": "798",
                "url": "https://production-app.io/config.js",
                "solution": "Remove secret from source."
            }
        ]
    }
    target = zap_parser.extract_target_url(generic_data)
    assert target == "https://production-app.io"

    findings = zap_parser.parse(generic_data)
    assert len(findings) == 2
    assert findings[0].name == "Cross-Site Scripting (Stored)"
    assert findings[0].severity == "High"
    assert findings[0].cwe_id == "CWE-79"
    assert findings[1].name == "Hardcoded Secret Key"
    assert findings[1].severity == "Critical"
    assert findings[1].cwe_id == "CWE-798"



