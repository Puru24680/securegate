"""
Tests for Release Gate Logic
Verifies deterministic PASS / REVIEW / BLOCK decisions based on findings and policy.
"""
from app.security.severity_engine import calculate_release_status

DEFAULT_POLICY = {
    'critical': 'BLOCK',
    'high': 'BLOCK',
    'medium': 'REVIEW',
    'low': 'PASS',
    'informational': 'PASS',
}


def test_release_gate_no_findings():
    status, reason, blocking, review = calculate_release_status([], DEFAULT_POLICY)
    assert status == "PASS"
    assert blocking == 0
    assert review == 0
    assert "cleared" in reason.lower() or "passed" in reason.lower()


def test_release_gate_low_only():
    findings = [
        {'severity': 'Low'},
        {'severity': 'Informational'}
    ]
    status, reason, blocking, review = calculate_release_status(findings, DEFAULT_POLICY)
    assert status == "PASS"
    assert blocking == 0
    assert review == 0
    assert "passed" in reason.lower()


def test_release_gate_medium_only():
    findings = [
        {'severity': 'Medium'},
        {'severity': 'Medium'},
        {'severity': 'Low'}
    ]
    status, reason, blocking, review = calculate_release_status(findings, DEFAULT_POLICY)
    assert status == "REVIEW"
    assert blocking == 0
    assert review == 2
    assert "review" in reason.lower()


def test_release_gate_high_finding():
    findings = [
        {'severity': 'High'},
        {'severity': 'Medium'},
        {'severity': 'Low'}
    ]
    status, reason, blocking, review = calculate_release_status(findings, DEFAULT_POLICY)
    assert status == "BLOCK"
    assert blocking == 1
    assert "blocked" in reason.lower()


def test_release_gate_critical_finding():
    findings = [
        {'severity': 'Critical'}
    ]
    status, reason, blocking, review = calculate_release_status(findings, DEFAULT_POLICY)
    assert status == "BLOCK"
    assert blocking == 1
    assert "blocked" in reason.lower()


def test_release_gate_mixed_findings():
    findings = [
        {'severity': 'Critical'},
        {'severity': 'High'},
        {'severity': 'High'},
        {'severity': 'Medium'},
        {'severity': 'Low'},
        {'severity': 'Informational'},
    ]
    status, reason, blocking, review = calculate_release_status(findings, DEFAULT_POLICY)
    assert status == "BLOCK"
    assert blocking == 3  # 1 Critical + 2 High
    assert "blocked" in reason.lower()


def test_release_gate_custom_policy():
    # User configured policy where Medium is also BLOCK
    strict_policy = {
        'critical': 'BLOCK',
        'high': 'BLOCK',
        'medium': 'BLOCK',
        'low': 'REVIEW',
        'informational': 'PASS',
    }
    findings = [{'severity': 'Medium'}]
    status, reason, blocking, review = calculate_release_status(findings, strict_policy)
    assert status == "BLOCK"
    assert blocking == 1
