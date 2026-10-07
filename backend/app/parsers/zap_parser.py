"""
ZAP JSON Report Parser
Parses OWASP ZAP JSON reports into normalized Finding objects.
"""
import json
import logging
from typing import Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ZAP risk level → normalized severity
RISK_MAP = {
    '3': 'High',
    '2': 'Medium',
    '1': 'Low',
    '0': 'Informational',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'informational': 'Informational',
    'info': 'Informational',
    'false positive': 'Informational',
}

CONFIDENCE_MAP = {
    '3': 'High',
    '2': 'Medium',
    '1': 'Low',
    '0': 'False Positive',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'confirmed': 'High',
}


@dataclass
class NormalizedFinding:
    name: str
    description: str
    severity: str
    confidence: str
    url: str
    method: str
    parameter: str
    evidence: str
    solution: str
    reference: str
    cwe_id: str
    plugin_id: str
    alert_ref: str
    instances: list = field(default_factory=list)


class ZAPParser:
    """Parses OWASP ZAP JSON reports."""

    def parse(self, raw_data: Any) -> list[NormalizedFinding]:
        """
        Parse ZAP JSON data.
        raw_data can be a dict (parsed JSON) or a string/bytes (raw JSON).
        Returns a list of NormalizedFinding objects.
        """
        if isinstance(raw_data, (str, bytes)):
            try:
                data = json.loads(raw_data)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Invalid JSON: {e}")
        elif isinstance(raw_data, (dict, list)):
            data = raw_data
        else:
            raise ValueError(f"Input must be a JSON string, dict, or list, got {type(raw_data).__name__}")

        alerts = self._extract_alerts(data)
        findings = []
        seen = set()

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            try:
                finding = self._normalize_alert(alert)
                # Deduplicate by name + url + parameter
                key = (finding.name.lower(), finding.url, finding.parameter)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse alert: {e} — skipping")
                continue

        return findings

    def _extract_alerts(self, data: Any) -> list[dict]:
        """Extract alerts from various ZAP JSON structures."""
        if isinstance(data, list):
            alerts = []
            for item in data:
                if isinstance(item, dict):
                    if 'alerts' in item:
                        sub = item.get('alerts', [])
                        alerts.extend(sub if isinstance(sub, list) else [sub])
                    elif 'alert' in item or 'name' in item or 'pluginId' in item:
                        alerts.append(item)
            return alerts if alerts else [x for x in data if isinstance(x, dict)]

        if not isinstance(data, dict):
            return []

        # If wrapped in "report" or "OWASPZAPReport"
        for wrapper_key in ['report', 'OWASPZAPReport', 'zapReport']:
            if wrapper_key in data and isinstance(data[wrapper_key], dict):
                data = data[wrapper_key]

        # Standard ZAP report format: { "site": [ { "alerts": [...] } ] }
        if 'site' in data:
            alerts = []
            sites = data['site']
            if isinstance(sites, list):
                for site in sites:
                    if isinstance(site, dict):
                        site_alerts = site.get('alerts', [])
                        if isinstance(site_alerts, list):
                            alerts.extend(site_alerts)
                        elif isinstance(site_alerts, dict):
                            alerts.append(site_alerts)
            elif isinstance(sites, dict):
                site_alerts = sites.get('alerts', [])
                if isinstance(site_alerts, list):
                    alerts.extend(site_alerts)
                elif isinstance(site_alerts, dict):
                    alerts.append(site_alerts)
            return alerts

        # Alternative: { "alerts": [...] }
        if 'alerts' in data:
            al = data['alerts']
            return al if isinstance(al, list) else [al] if isinstance(al, dict) else []

        # Alternative: dictionary with alerts somewhere inside
        for key, val in data.items():
            if isinstance(val, list) and val and isinstance(val[0], dict) and ('alert' in val[0] or 'name' in val[0] or 'pluginId' in val[0]):
                return val

        if 'alert' in data or 'name' in data or 'pluginId' in data:
            return [data]

        logger.warning("Could not locate alerts array in ZAP report")
        return []

    def _normalize_alert(self, alert: dict) -> NormalizedFinding:
        """Normalize a single ZAP alert dict."""
        name = (
            alert.get('alert') or
            alert.get('name') or
            alert.get('pluginId', 'Unknown Finding')
        )
        if not name:
            name = 'Unknown Finding'

        # Severity
        riskcode = str(alert.get('riskcode', '')).strip()
        risk_raw = str(alert.get('risk', alert.get('riskdesc', alert.get('riskDesc', '')))).lower()

        if riskcode == '4':
            severity = 'Critical'
        elif riskcode == '3':
            severity = 'High'
        elif riskcode == '2':
            severity = 'Medium'
        elif riskcode == '1':
            severity = 'Low'
        elif riskcode == '0':
            severity = 'Informational'
        elif 'critical' in risk_raw:
            severity = 'Critical'
        elif 'high' in risk_raw:
            severity = 'High'
        elif 'medium' in risk_raw or 'moderate' in risk_raw:
            severity = 'Medium'
        elif 'informational' in risk_raw or 'info' in risk_raw or 'false positive' in risk_raw:
            severity = 'Informational'
        elif 'low' in risk_raw:
            severity = 'Low'
        else:
            severity = 'Low'

        # Confidence
        conf_raw = str(alert.get('confidence', alert.get('confidenceDesc', '2'))).lower()
        confidence = CONFIDENCE_MAP.get(conf_raw, 'Medium')

        # URL / method / parameter from instances or direct fields
        instances = alert.get('instances', [])
        if instances and isinstance(instances, list) and len(instances) > 0:
            first = instances[0]
            url = first.get('uri', first.get('url', ''))
            method = first.get('method', 'GET')
            parameter = first.get('param', first.get('parameter', ''))
            evidence = first.get('evidence', first.get('attack', ''))
        else:
            url = alert.get('url', alert.get('uri', ''))
            method = alert.get('method', 'GET')
            parameter = alert.get('param', alert.get('parameter', ''))
            evidence = alert.get('evidence', alert.get('attack', ''))

        # CWE
        cwe_raw = alert.get('cweid', alert.get('cweId', alert.get('cwe', '')))
        if cwe_raw and str(cwe_raw) not in ('', '-1', '0'):
            cwe_id = f"CWE-{cwe_raw}"
        else:
            cwe_id = 'N/A'

        return NormalizedFinding(
            name=str(name).strip(),
            description=str(alert.get('desc', alert.get('description', ''))).strip(),
            severity=severity,
            confidence=confidence,
            url=str(url).strip(),
            method=str(method).upper().strip() or 'GET',
            parameter=str(parameter).strip(),
            evidence=str(evidence).strip(),
            solution=str(alert.get('solution', '')).strip(),
            reference=str(alert.get('reference', '')).strip(),
            cwe_id=cwe_id,
            plugin_id=str(alert.get('pluginid', alert.get('pluginId', ''))).strip(),
            alert_ref=str(alert.get('alertRef', alert.get('alert_ref', ''))).strip(),
            instances=instances,
        )


# Singleton
zap_parser = ZAPParser()
