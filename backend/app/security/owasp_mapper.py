"""
OWASP Top 10 (2021) and CWE Mapping Layer
Maps ZAP finding names to OWASP categories and CWE IDs.
"""
import re

# -------------------------------------------------------------------
# Master mapping: pattern → (owasp_category, cwe_id)
# Patterns are matched case-insensitively against the finding name.
# -------------------------------------------------------------------
OWASP_MAPPING = [
    # A01: Broken Access Control
    (r'broken access control|directory listing|path traversal|insecure direct object|'
     r'authorization|privilege escalation|forced browsing|idor|access control',
     'A01:2021 - Broken Access Control', 'CWE-284'),

    # A02: Cryptographic Failures
    (r'ssl|tls|weak cipher|certificate|https|cleartext|plain.?text password|'
     r'sensitive data exposure|cryptograph|hash|md5|sha.?1(?!\d)|weak.?hash|'
     r'cookie without secure|cookie no secure flag|cookie not httponly|'
     r'transport layer|heartbleed',
     'A02:2021 - Cryptographic Failures', 'CWE-327'),

    # A03: Injection
    (r'sql injection|sqli|blind sql|command injection|os command|code injection|'
     r'ldap injection|xpath injection|xml injection|expression language injection|'
     r'template injection|ssti|log injection|header injection|'
     r'cross.?site scripting|xss|stored xss|reflected xss|dom.?based xss|'
     r'script injection|crlf injection|http response splitting',
     'A03:2021 - Injection', 'CWE-89'),

    # A04: Insecure Design
    (r'insecure design|threat model|security requirement|design flaw',
     'A04:2021 - Insecure Design', 'CWE-657'),

    # A05: Security Misconfiguration
    (r'security misconfiguration|misconfigur|x-frame-options|content-security-policy|'
     r'x-content-type|clickjack|server.?banner|version disclosure|error.?message|'
     r'stack trace|debug|default credential|unnecessary feature|'
     r'cors|cross.?origin|http methods|options method|trace method|'
     r'strict.?transport|hsts|anti.?csrf|csrf token missing|'
     r'referrer.?policy|permissions.?policy|feature.?policy|'
     r'cache.?control|pragma|expires|information disclosure|'
     r'charset not defined|charset missing|x-powered-by',
     'A05:2021 - Security Misconfiguration', 'CWE-16'),

    # A06: Vulnerable and Outdated Components
    (r'outdated|vulnerable component|known vulnerability|cve.?20|obsolete|'
     r'end.?of.?life|deprecated library|third.?party',
     'A06:2021 - Vulnerable and Outdated Components', 'CWE-1104'),

    # A07: Identification and Authentication Failures
    (r'authentication|brute.?force|credential|session fixation|session hijack|'
     r'weak password|default password|insecure login|remember me|'
     r'multi.?factor|mfa|2fa|account lockout|session timeout|'
     r'jwt|json web token|cookie|session management',
     'A07:2021 - Identification and Authentication Failures', 'CWE-287'),

    # A08: Software and Data Integrity Failures
    (r'integrity|deserialization|unsafe deserialization|insecure deserialization|'
     r'subresource integrity|sri|auto.?update|ci.?cd',
     'A08:2021 - Software and Data Integrity Failures', 'CWE-502'),

    # A09: Security Logging and Monitoring Failures
    (r'logging|monitoring|audit|log.?forging|insufficient logging|'
     r'log injection',
     'A09:2021 - Security Logging and Monitoring Failures', 'CWE-778'),

    # A10: Server-Side Request Forgery
    (r'ssrf|server.?side request forgery|internal network|'
     r'internal service|metadata service',
     'A10:2021 - Server-Side Request Forgery', 'CWE-918'),
]

# Compile patterns
_COMPILED = [
    (re.compile(pattern, re.IGNORECASE), owasp, cwe)
    for pattern, owasp, cwe in OWASP_MAPPING
]

# CWE-specific overrides from ZAP's own CWE IDs → OWASP
CWE_TO_OWASP = {
    '89': ('A03:2021 - Injection', 'CWE-89'),           # SQL Injection
    '79': ('A03:2021 - Injection', 'CWE-79'),            # XSS
    '78': ('A03:2021 - Injection', 'CWE-78'),            # OS Command Injection
    '90': ('A03:2021 - Injection', 'CWE-90'),            # LDAP Injection
    '643': ('A03:2021 - Injection', 'CWE-643'),          # XPath Injection
    '116': ('A03:2021 - Injection', 'CWE-116'),          # Improper Encoding
    '93': ('A03:2021 - Injection', 'CWE-93'),            # CRLF Injection
    '113': ('A03:2021 - Injection', 'CWE-113'),          # HTTP Response Splitting
    '284': ('A01:2021 - Broken Access Control', 'CWE-284'),
    '285': ('A01:2021 - Broken Access Control', 'CWE-285'),
    '22': ('A01:2021 - Broken Access Control', 'CWE-22'),   # Path Traversal
    '327': ('A02:2021 - Cryptographic Failures', 'CWE-327'),
    '326': ('A02:2021 - Cryptographic Failures', 'CWE-326'),
    '261': ('A02:2021 - Cryptographic Failures', 'CWE-261'),
    '310': ('A02:2021 - Cryptographic Failures', 'CWE-310'),
    '319': ('A02:2021 - Cryptographic Failures', 'CWE-319'),
    '614': ('A02:2021 - Cryptographic Failures', 'CWE-614'),  # Cookie no Secure
    '1004': ('A07:2021 - Identification and Authentication Failures', 'CWE-1004'), # Cookie no HttpOnly
    '16': ('A05:2021 - Security Misconfiguration', 'CWE-16'),
    '693': ('A05:2021 - Security Misconfiguration', 'CWE-693'),  # Missing CSP
    '1021': ('A05:2021 - Security Misconfiguration', 'CWE-1021'),  # Clickjacking
    '287': ('A07:2021 - Identification and Authentication Failures', 'CWE-287'),
    '307': ('A07:2021 - Identification and Authentication Failures', 'CWE-307'),
    '502': ('A08:2021 - Software and Data Integrity Failures', 'CWE-502'),
    '918': ('A10:2021 - Server-Side Request Forgery', 'CWE-918'),
    '352': ('A05:2021 - Security Misconfiguration', 'CWE-352'),   # CSRF
    '200': ('A05:2021 - Security Misconfiguration', 'CWE-200'),   # Info Disclosure
    '209': ('A05:2021 - Security Misconfiguration', 'CWE-209'),   # Error info in response
    '778': ('A09:2021 - Security Logging and Monitoring Failures', 'CWE-778'),
}


def map_finding(name: str, zap_cwe: str = 'N/A') -> tuple[str, str]:
    """
    Map a finding name + optional ZAP-provided CWE to OWASP category and CWE.
    Returns (owasp_category, cwe_id).
    """
    # 1. Try name-based pattern matching (most specific)
    for pattern, owasp, cwe in _COMPILED:
        if pattern.search(name):
            # Use ZAP's own CWE if it's specific, else use our mapped CWE
            resolved_cwe = zap_cwe if _valid_cwe(zap_cwe) else cwe
            return owasp, resolved_cwe

    # 2. Try CWE-based mapping from ZAP's supplied CWE
    if _valid_cwe(zap_cwe):
        cwe_num = zap_cwe.replace('CWE-', '').strip()
        if cwe_num in CWE_TO_OWASP:
            return CWE_TO_OWASP[cwe_num]
        # Return unmapped but keep the CWE
        return 'Unmapped', zap_cwe

    return 'Unmapped', 'N/A'


def _valid_cwe(cwe: str) -> bool:
    """Check if a CWE string is valid (not N/A or empty)."""
    return bool(cwe and cwe.strip() and cwe.strip().upper() not in ('N/A', 'NONE', '-1', ''))


def get_owasp_year(category: str) -> str:
    """Extract year from OWASP category string."""
    if '2021' in category:
        return '2021'
    if '2017' in category:
        return '2017'
    return '2021'
