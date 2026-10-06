"""
Tests for OWASP Top 10 and CWE Mapper
"""
from app.security.owasp_mapper import map_finding


def test_sql_injection_mapping():
    cat, cwe = map_finding("SQL Injection", zap_cwe="89")
    assert "A03:2021 - Injection" in cat
    assert cwe == "CWE-89" or cwe == "89"


def test_xss_mapping():
    cat, cwe = map_finding("Cross Site Scripting (Reflected)", zap_cwe="79")
    assert "A03:2021 - Injection" in cat
    assert "79" in cwe


def test_broken_access_control_mapping():
    cat, cwe = map_finding("Path Traversal / Insecure Direct Object Access", zap_cwe="22")
    assert "A01:2021 - Broken Access Control" in cat


def test_security_misconfiguration_mapping():
    cat, cwe = map_finding("Missing Anti-clickjacking Header (X-Frame-Options)")
    assert "A05:2021 - Security Misconfiguration" in cat


def test_cryptographic_failures_mapping():
    cat, cwe = map_finding("Cookie No Secure Flag")
    assert "A02:2021 - Cryptographic Failures" in cat


def test_unmapped_finding():
    cat, cwe = map_finding("Random Obscure Proprietary Warning", zap_cwe="N/A")
    assert cat == "Unmapped"
    assert cwe == "N/A"


def test_unmapped_with_valid_zap_cwe():
    cat, cwe = map_finding("Custom Proprietary Tool Notice", zap_cwe="CWE-999")
    assert cat == "Unmapped"
    assert cwe == "CWE-999"
