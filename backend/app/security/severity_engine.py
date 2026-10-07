"""
Severity Engine
Normalizes ZAP risk levels, calculates scores, and determines release gate status.
"""
from .owasp_mapper import map_finding, get_owasp_year

# Severity → numeric score
SEVERITY_SCORES = {
    'Critical': 100,
    'High': 80,
    'Medium': 50,
    'Low': 20,
    'Informational': 5,
}

# Confidence multipliers
CONFIDENCE_MULTIPLIERS = {
    'High': 1.0,
    'Medium': 0.8,
    'Low': 0.6,
    'False Positive': 0.1,
}

SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational']


def normalize_severity(raw_severity: str) -> str:
    """Normalize any severity string to canonical form."""
    s = str(raw_severity).strip().lower()
    mapping = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'moderate': 'Medium',
        'low': 'Low',
        'informational': 'Informational',
        'info': 'Informational',
        'false positive': 'Informational',
        '4': 'Critical',
        '3': 'High',
        '2': 'Medium',
        '1': 'Low',
        '0': 'Informational',
    }
    return mapping.get(s, 'Low')


def calculate_contextual_risk_score(
    severity: str,
    confidence: str = 'Medium',
    cvss_score: float = 0.0,
    asset_criticality: str = 'Medium',
    environment: str = 'Development',
    recurrence_count: int = 1
) -> tuple[float, str, str]:
    """
    Deterministic multi-factor risk engine:
    Evaluates:
      - Canonical Severity (Base weight)
      - CVSS Score (blends with severity if > 0)
      - Scanner Confidence
      - Asset Criticality (Impact multiplier)
      - Deployment Environment (Production > Staging > Development)
      - Recurrence (Age/recurrence penalty)
    Returns:
      (risk_score: 0.0 - 100.0, priority: str, recommended_action: str)
    """
    canonical_sev = normalize_severity(severity)
    base = SEVERITY_SCORES.get(canonical_sev, 20)

    if cvss_score and cvss_score > 0.0:
        cvss_component = min(10.0, max(0.0, cvss_score)) * 10.0
        base = (base * 0.6) + (cvss_component * 0.4)

    conf_mult = {
        'High': 1.0,
        'Medium': 0.85,
        'Low': 0.65,
        'False Positive': 0.05,
    }.get(confidence, 0.85)

    asset_mult = {
        'Critical': 1.25,
        'High': 1.10,
        'Medium': 1.00,
        'Low': 0.85,
    }.get(asset_criticality, 1.00)

    env_mult = {
        'Production': 1.20,
        'Staging': 1.05,
        'Development': 0.90,
    }.get(environment, 0.90)

    rec_mult = 1.15 if recurrence_count >= 3 else (1.08 if recurrence_count == 2 else 1.0)

    calculated = base * conf_mult * asset_mult * env_mult * rec_mult
    risk_score = min(100.0, max(0.0, round(calculated, 1)))

    if risk_score >= 80.0:
        priority = "P0 - Blocker"
        action = "Immediate remediation required. Blocks release gates. Notify security lead."
    elif risk_score >= 60.0:
        priority = "P1 - High"
        action = "Remediate prior to production release. High exploitability or asset exposure."
    elif risk_score >= 35.0:
        priority = "P2 - Medium"
        action = "Prioritize in current sprint cycle. Implement defensive mitigations."
    elif risk_score >= 15.0:
        priority = "P3 - Low"
        action = "Resolve during routine maintenance or code hygiene sprint."
    else:
        priority = "P4 - Informational"
        action = "Informational observation. Review security best practices or accept risk."

    return risk_score, priority, action


def calculate_risk_score(severity: str, confidence: str) -> float:
    """Calculate baseline risk score for a single finding."""
    canonical_sev = normalize_severity(severity)
    base = SEVERITY_SCORES.get(canonical_sev, 20)
    multiplier = CONFIDENCE_MULTIPLIERS.get(confidence, 0.8)
    return round(base * multiplier, 1)


def calculate_security_score(findings: list) -> float:
    """
    Calculate overall security score (0-100).
    Score decreases with high-severity findings.
    Algorithm is deterministic and explainable.
    """
    if not findings:
        return 100.0

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        severity = normalize_severity(f.get('severity', 'Low') if isinstance(f, dict) else f.severity)
        counts[severity] = counts.get(severity, 0) + 1

    # Penalty weights per finding type
    penalties = {
        'Critical': 25.0,
        'High': 12.0,
        'Medium': 4.0,
        'Low': 1.0,
        'Informational': 0.0,
    }

    total_penalty = 0.0
    for severity, count in counts.items():
        # Diminishing returns: each additional finding of same severity adds less
        for i in range(count):
            factor = 1.0 / (1 + i * 0.3)
            total_penalty += penalties[severity] * factor

    score = max(0.0, 100.0 - total_penalty)
    return round(score, 1)


def calculate_release_status(findings: list, policy: dict) -> tuple[str, str, int, int]:
    """
    Evaluate release gate status.
    Returns (status, reason, blocking_count, review_count).
    policy: { 'critical': 'BLOCK', 'high': 'BLOCK', 'medium': 'REVIEW', ... }
    """
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        severity = normalize_severity(f.get('severity', 'Low') if isinstance(f, dict) else f.severity)
        counts[severity] += 1

    # Default policy
    default_policy = {
        'critical': 'BLOCK',
        'high': 'BLOCK',
        'medium': 'REVIEW',
        'low': 'PASS',
        'informational': 'PASS',
    }
    if policy:
        default_policy.update({k.lower(): v for k, v in policy.items()})

    blocking_count = 0
    review_count = 0
    block_reasons = []
    review_reasons = []

    for severity in SEVERITY_ORDER:
        count = counts[severity]
        if count == 0:
            continue
        action = default_policy.get(severity.lower(), 'PASS').upper()
        if action == 'BLOCK':
            blocking_count += count
            block_reasons.append(f"{count} {severity}")
        elif action == 'REVIEW':
            review_count += count
            review_reasons.append(f"{count} {severity}")

    if blocking_count > 0:
        reason = f"Release blocked due to: {', '.join(block_reasons)}. Critical/High findings violate the release policy."
        return 'BLOCK', reason, blocking_count, review_count
    elif review_count > 0:
        reason = f"Release requires review due to: {', '.join(review_reasons)}. Medium severity findings require security sign-off."
        return 'REVIEW', reason, 0, review_count
    else:
        reason = "Release passed. No High or Critical vulnerabilities were detected. The release can proceed."
        return 'PASS', reason, 0, 0


def enrich_finding(finding_data: dict, policy: dict = None) -> dict:
    """
    Enrich a finding dict with OWASP mapping, risk score, severity normalization.
    """
    name = finding_data.get('name', '')
    zap_cwe = finding_data.get('cwe_id', 'N/A')
    severity = normalize_severity(finding_data.get('severity', 'Low'))
    confidence = finding_data.get('confidence', 'Medium')

    owasp_cat, cwe_id = map_finding(name, zap_cwe)
    risk_score = calculate_risk_score(severity, confidence)

    return {
        **finding_data,
        'severity': severity,
        'owasp_category': owasp_cat,
        'owasp_year': get_owasp_year(owasp_cat),
        'cwe_id': cwe_id,
        'risk_score': risk_score,
    }
