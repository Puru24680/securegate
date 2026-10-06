"""
AI Security Analyst Service
Provides AI-assisted vulnerability analysis using OpenAI if configured.
Deterministic security logic remains separate and authoritative.
"""
import os
import re
from typing import Optional, Dict, Any

# Pattern for sanitizing credentials/tokens from evidence/urls
SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(bearer\s+[a-z0-9_\-\.]{20,})'),
    re.compile(r'(?i)(password|passwd|secret|apikey|api_key|token)\s*[:=]\s*["\']?([^"\'\s&]+)'),
    re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']?([^"\'\s&]+)'),
]


def sanitize_text(text: str) -> str:
    """Sanitize sensitive credentials, secrets, or keys before sending to LLM."""
    if not text:
        return ""
    sanitized = text
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r'\1: [REDACTED_BY_SECUREGATE]', sanitized)
    return sanitized


class AIService:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY", "").strip()

    def is_available(self) -> bool:
        return bool(self.api_key)

    def explain_vulnerability(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a vulnerability and produce:
        - plain-English explanation
        - business impact
        - technical impact
        - recommended remediation
        - developer action items
        """
        name = finding_data.get("name", "Unknown Vulnerability")
        severity = finding_data.get("severity", "Low")
        cwe_id = finding_data.get("cwe_id", "N/A")
        owasp_cat = finding_data.get("owasp_category", "Unmapped")
        endpoint = sanitize_text(finding_data.get("url", ""))
        method = finding_data.get("method", "GET")
        parameter = sanitize_text(finding_data.get("parameter", ""))
        evidence = sanitize_text(finding_data.get("evidence", ""))
        description = sanitize_text(finding_data.get("description", ""))

        if not self.is_available():
            return {
                "available": False,
                "provider": "None",
                "message": "AI analysis unavailable — configure OPENAI_API_KEY environment variable.",
                "analysis": self._generate_heuristic_advisory(
                    name=name,
                    severity=severity,
                    owasp_cat=owasp_cat,
                    cwe_id=cwe_id,
                    endpoint=endpoint,
                    parameter=parameter
                )
            }

        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)

            prompt = f"""You are a Principal Application Security Engineer reviewing a static/dynamic security scan finding.
Provide an actionable security review in JSON format for developers.

Vulnerability Details:
- Title: {name}
- Severity: {severity}
- OWASP Category: {owasp_cat}
- CWE: {cwe_id}
- Affected Endpoint: {method} {endpoint}
- Parameter: {parameter}
- Evidence Preview: {evidence[:300]}
- Scanner Description: {description[:400]}

Respond strictly with valid JSON with these exact keys:
{{
  "plain_english_explanation": "2-3 sentences explaining in simple terms what this issue means for the application.",
  "business_impact": "Financial, regulatory, customer trust, or operational consequences.",
  "technical_impact": "Exploitability, data exposure, system compromise, or privilege escalation vector.",
  "recommended_remediation": "Clear architectural or code-level prevention strategies.",
  "developer_action_items": ["Step 1", "Step 2", "Step 3"]
}}"""

            response = client.chat.completions.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                messages=[
                    {"role": "system", "content": "You are SecureGate's AI AppSec Advisor. Deliver crisp, technical, high-value AppSec guidance."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )

            import json
            content = response.choices[0].message.content
            parsed = json.loads(content)

            return {
                "available": True,
                "provider": "OpenAI",
                "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                "analysis": parsed
            }
        except Exception as e:
            return {
                "available": False,
                "provider": "OpenAI (Error)",
                "message": f"AI query failed: {str(e)}",
                "analysis": self._generate_heuristic_advisory(
                    name=name,
                    severity=severity,
                    owasp_cat=owasp_cat,
                    cwe_id=cwe_id,
                    endpoint=endpoint,
                    parameter=parameter
                )
            }

    def _generate_heuristic_advisory(self, name: str, severity: str, owasp_cat: str, cwe_id: str, endpoint: str, parameter: str) -> Dict[str, Any]:
        """Built-in deterministic AppSec advisory when no OpenAI key is configured."""
        param_desc = f" affecting parameter '{parameter}'" if parameter else ""
        return {
            "plain_english_explanation": f"The security scanner identified a potential {name} vulnerability{param_desc} on endpoint '{endpoint}'. This indicates that incoming inputs or server configurations are not sufficiently validated or hardened before processing.",
            "business_impact": f"Classified as {severity} risk under {owasp_cat}. Depending on attacker access, this may lead to unintended disclosure of proprietary business data, violation of compliance frameworks (SOC2, PCI-DSS, GDPR), or compromised service integrity.",
            "technical_impact": f"Referenced by {cwe_id}. Attackers could exploit this flaw to bypass authentication/authorization controls, inject arbitrary instructions, or exfiltrate state headers from client sessions.",
            "recommended_remediation": "Adopt defense-in-depth principles: enforce strict schema validation on all inputs, implement parameterized abstractions (prepared statements, contextual escaping), and configure restrictive Content Security and Transport Security headers.",
            "developer_action_items": [
                f"Inspect the code handling '{endpoint}' and verify sanitization on parameter '{parameter or 'request payload'}'.",
                "Add automated regression unit/integration tests asserting rejection of hostile payloads.",
                f"Verify that HTTP responses adhere to modern secure header baselines ({cwe_id})."
            ]
        }


ai_service = AIService()
