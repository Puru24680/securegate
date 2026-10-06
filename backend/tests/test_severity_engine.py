"""
Tests for Severity Engine and Risk Calculation
"""
from app.security.severity_engine import (
    normalize_severity,
    calculate_risk_score,
    calculate_security_score,
    enrich_finding
)


def test_normalize_severity():
    assert normalize_severity("CRITICAL") == "Critical"
    assert normalize_severity("high") == "High"
    assert normalize_severity("3") == "High"
    assert normalize_severity("medium") == "Medium"
    assert normalize_severity("moderate") == "Medium"
    assert normalize_severity("low") == "Low"
    assert normalize_severity("informational") == "Informational"
    assert normalize_severity("info") == "Informational"
    assert normalize_severity("unknown_xyz") == "Low"


def test_calculate_risk_score():
    score_crit = calculate_risk_score("Critical", "High")
    score_high = calculate_risk_score("High", "High")
    score_med = calculate_risk_score("Medium", "High")
    score_low = calculate_risk_score("Low", "High")

    assert score_crit > score_high > score_med > score_low
    assert score_crit == 100.0
    assert score_high == 80.0


def test_security_score_empty():
    assert calculate_security_score([]) == 100.0


def test_security_score_decreases_with_severity():
    findings_clean = []
    findings_low = [{'severity': 'Low'}]
    findings_medium = [{'severity': 'Medium'}]
    findings_high = [{'severity': 'High'}]
    findings_critical = [{'severity': 'Critical'}]

    score_clean = calculate_security_score(findings_clean)
    score_low = calculate_security_score(findings_low)
    score_med = calculate_security_score(findings_medium)
    score_high = calculate_security_score(findings_high)
    score_crit = calculate_security_score(findings_critical)

    assert score_clean > score_low > score_med > score_high > score_crit
    assert score_clean == 100.0
    assert score_crit < 80.0


def test_enrich_finding():
    raw = {
        "name": "SQL Injection",
        "severity": "high",
        "confidence": "High",
        "cwe_id": "89"
    }
    enriched = enrich_finding(raw)
    assert enriched["severity"] == "High"
    assert "Injection" in enriched["owasp_category"]
    assert enriched["risk_score"] == 80.0
