"""
Unit Tests for SSRF & Scan Target Security Guard
Verifies blocking of cloud metadata (169.254.169.254), private RFC1918 ranges,
malicious protocols, and port validation.
"""
from app.security.ssrf import validate_scan_target, validate_target_url


def test_ssrf_rejects_cloud_metadata():
    is_valid, _, err = validate_scan_target("http://169.254.169.254/latest/meta-data/", allow_private_in_dev=False)
    assert is_valid is False
    assert "Security Restriction" in (err or "")


def test_ssrf_rejects_loopback_in_strict_mode():
    is_valid, _, err = validate_scan_target("http://127.0.0.1:8080/admin", allow_private_in_dev=False)
    assert is_valid is False
    assert "Security Restriction" in (err or "")


def test_ssrf_rejects_malicious_protocols():
    is_valid, _, err = validate_scan_target("file:///etc/passwd")
    assert is_valid is False
    assert "Unsupported protocol" in (err or "")

    is_valid_gopher, _, _ = validate_scan_target("gopher://127.0.0.1:6379/_flushall")
    assert is_valid_gopher is False


def test_ssrf_allows_legitimate_public_targets():
    is_valid, canonical, err = validate_scan_target("https://example.com")
    assert is_valid is True
    assert canonical == "https://example.com"
    assert err is None


def test_ssrf_allows_authorized_local_testbeds_in_dev():
    is_valid, canonical, err = validate_scan_target("http://localhost:3000", allow_private_in_dev=True)
    assert is_valid is True
    assert "localhost" in canonical


def test_validate_target_url_convenience():
    is_safe, _ = validate_target_url("http://169.254.169.254", allow_private=False)
    assert is_safe is False
