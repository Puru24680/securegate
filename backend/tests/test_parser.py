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
