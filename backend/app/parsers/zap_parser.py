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

    def extract_target_url(self, raw_data: Any) -> str | None:
        """Extract authoritative target URL or hostname from any vulnerability report."""
        if isinstance(raw_data, (str, bytes)):
            try:
                data = json.loads(raw_data)
            except Exception:
                return None
        elif isinstance(raw_data, (dict, list)):
            data = raw_data
        else:
            return None

        # Check list of items (e.g. list of alerts, sites, or finding objects)
        if isinstance(data, list):
            if not data:
                return None
            first_item = data[0]
            if isinstance(first_item, dict):
                if 'site' in first_item or 'sites' in first_item or 'alerts' in first_item:
                    return self.extract_target_url(first_item)
                first_url = (
                    first_item.get('url') or
                    first_item.get('uri') or
                    first_item.get('target') or
                    first_item.get('host') or
                    first_item.get('matched-at')
                )
                if first_url and str(first_url).startswith('http'):
                    try:
                        from urllib.parse import urlparse
                        p = urlparse(first_url)
                        return f"{p.scheme}://{p.netloc}"
                    except Exception:
                        return str(first_url).strip()
            return None

        # Check standard site array or dict
        sites = data.get('site') or data.get('sites')
        if isinstance(sites, list) and sites and isinstance(sites[0], dict):
            target = sites[0].get('@name') or sites[0].get('name') or sites[0].get('host')
            if target and str(target).strip():
                return str(target).strip()
        elif isinstance(sites, dict):
            target = sites.get('@name') or sites.get('name') or sites.get('host')
            if target and str(target).strip():
                return str(target).strip()

        # Check target or url at root
        for root_key in ['target', 'target_url', 'targetUrl', 'url', 'host']:
            if data.get(root_key) and isinstance(data[root_key], str):
                return data[root_key].strip()

        # Check wrapper keys
        for wrapper in ['report', 'OWASPZAPReport', 'zapReport', 'Report']:
            if wrapper in data and isinstance(data[wrapper], (dict, list)):
                res = self.extract_target_url(data[wrapper])
                if res:
                    return res

        # Fallback: extract from first alert's URL if available
        alerts = self._extract_alerts(data)
        if alerts and isinstance(alerts, list):
            for alert_item in alerts:
                if not isinstance(alert_item, dict):
                    continue
                instances = alert_item.get('instances', alert_item.get('occurrences', []))
                if isinstance(instances, dict):
                    instances = instances.get('instance') or [instances]
                if isinstance(instances, list) and instances and isinstance(instances[0], dict):
                    cand = instances[0].get('uri') or instances[0].get('url')
                    if cand and str(cand).startswith('http'):
                        try:
                            from urllib.parse import urlparse
                            p = urlparse(cand)
                            return f"{p.scheme}://{p.netloc}"
                        except Exception:
                            pass
                cand_url = alert_item.get('url') or alert_item.get('uri') or alert_item.get('matched-at')
                if cand_url and str(cand_url).startswith('http'):
                    try:
                        from urllib.parse import urlparse
                        p = urlparse(cand_url)
                        return f"{p.scheme}://{p.netloc}"
                    except Exception:
                        pass

        return None

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
                # Deduplicate by name + url + parameter + plugin_id
                key = (finding.name.lower(), finding.url.lower(), finding.parameter.lower(), finding.plugin_id)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse alert: {e} — skipping")
                continue

        return findings

    def _extract_alerts(self, data: Any) -> list[dict]:
        """
        Universal alert extractor supporting:
        - ZAP Traditional JSON: site[].alerts[]
        - ZAP XML-to-JSON: site.alerts.alertitem[] or site.alerts.alert[]
        - ZAP API format: alerts[]
        - Generic security reports: findings[], vulnerabilities[], issues[], results[]
        - Flat list of alerts
        """
        if isinstance(data, list):
            alerts = []
            for item in data:
                if isinstance(item, dict):
                    # Check if this item is a container of alerts
                    if any(k in item for k in ['alerts', 'findings', 'vulnerabilities', 'issues', 'alertitem']):
                        sub = self._extract_alerts(item)
                        alerts.extend(sub)
                    elif any(k in item for k in ['alert', 'name', 'title', 'pluginId', 'risk', 'severity', 'vulnerability']):
                        alerts.append(item)
            return alerts if alerts else [x for x in data if isinstance(x, dict)]

        if not isinstance(data, dict):
            return []

        # Check common top-level wrapper keys
        for wrapper_key in ['report', 'OWASPZAPReport', 'zapReport', 'Report', 'scan', 'data']:
            if wrapper_key in data and isinstance(data[wrapper_key], (dict, list)):
                res = self._extract_alerts(data[wrapper_key])
                if res:
                    return res

        # 1. ZAP format: site (list or dict)
        sites = data.get('site') or data.get('sites')
        if sites:
            alerts = []
            site_list = sites if isinstance(sites, list) else [sites]
            for s in site_list:
                if not isinstance(s, dict):
                    continue
                s_alerts = s.get('alerts') or s.get('alert') or s.get('findings')
                if isinstance(s_alerts, list):
                    alerts.extend(s_alerts)
                elif isinstance(s_alerts, dict):
                    # XML-to-JSON conversions often wrap items in alertitem or alert
                    if 'alertitem' in s_alerts and isinstance(s_alerts['alertitem'], list):
                        alerts.extend(s_alerts['alertitem'])
                    elif 'alert' in s_alerts and isinstance(s_alerts['alert'], list):
                        alerts.extend(s_alerts['alert'])
                    elif 'item' in s_alerts and isinstance(s_alerts['item'], list):
                        alerts.extend(s_alerts['item'])
                    else:
                        alerts.append(s_alerts)
            if alerts:
                return alerts

        # 2. Check top-level lists
        for key in ['alerts', 'findings', 'vulnerabilities', 'issues', 'results', 'items', 'rules']:
            if key in data:
                val = data[key]
                if isinstance(val, list):
                    return val
                elif isinstance(val, dict):
                    if 'alertitem' in val and isinstance(val['alertitem'], list):
                        return val['alertitem']
                    elif 'alert' in val and isinstance(val['alert'], list):
                        return val['alert']
                    return [val]

        # 3. Search any key that contains a list of vulnerability dicts
        for key, val in data.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                first = val[0]
                if any(k in first for k in ['alert', 'name', 'title', 'pluginId', 'risk', 'severity', 'cweid', 'url', 'uri', 'vulnerability']):
                    return val

        # 4. Single root alert dictionary
        if any(k in data for k in ['alert', 'name', 'pluginId', 'risk', 'severity', 'vulnerability']):
            return [data]

        logger.warning("Could not locate alerts array in report")
        return []

    def _normalize_alert(self, alert: dict) -> NormalizedFinding:
        """Normalize a single alert dict into standard NormalizedFinding schema."""
        info = alert.get('info') if isinstance(alert.get('info'), dict) else {}

        # 1. Vulnerability Name
        name = (
            alert.get('alert') or
            alert.get('name') or
            alert.get('title') or
            info.get('name') or
            info.get('title') or
            alert.get('vulnerability') or
            alert.get('rule_name') or
            alert.get('pluginId') or
            'Unknown Vulnerability'
        )
        if isinstance(name, (list, dict)):
            name = str(alert.get('name') or alert.get('title') or alert.get('alert') or 'Security Finding')

        # 2. Authoritative Severity Classification
        # ZAP risk codes: 4=Critical, 3=High, 2=Medium, 1=Low, 0=Informational
        riskcode = str(alert.get('riskcode', alert.get('risk_code', ''))).strip()

        # Risk strings: isolate the risk term before any confidence in parentheses, e.g. "Informational (Medium)" -> "informational"
        raw_sev_str = str(
            alert.get('risk') or
            alert.get('riskdesc') or
            alert.get('riskDesc') or
            alert.get('severity') or
            info.get('severity') or
            alert.get('level') or
            ''
        ).strip().lower()

        # Separate risk and confidence from format like "High (Medium)" or "Informational (High)"
        risk_part = raw_sev_str.split('(')[0].strip() if '(' in raw_sev_str else raw_sev_str
        conf_from_desc = raw_sev_str.split('(')[1].replace(')', '').strip() if '(' in raw_sev_str else ''

        if riskcode == '4' or 'critical' in risk_part:
            severity = 'Critical'
        elif riskcode == '3' or 'high' in risk_part:
            severity = 'High'
        elif riskcode == '2' or 'medium' in risk_part or 'moderate' in risk_part or 'warn' in risk_part:
            severity = 'Medium'
        elif riskcode == '1' or 'low' in risk_part:
            severity = 'Low'
        elif riskcode == '0' or 'informational' in risk_part or 'info' in risk_part or 'false positive' in risk_part:
            severity = 'Informational'
        else:
            # Fallback based on CVSS or keyword heuristic
            try:
                cvss = float(alert.get('cvss', alert.get('cvss_score', alert.get('score', -1))))
                if cvss >= 9.0: severity = 'Critical'
                elif cvss >= 7.0: severity = 'High'
                elif cvss >= 4.0: severity = 'Medium'
                elif cvss >= 0.1: severity = 'Low'
                elif cvss == 0.0: severity = 'Informational'
                else:
                    severity = 'High' if any(w in str(name).lower() for w in ['injection', 'rce', 'overflow', 'bypass']) else 'Low'
            except (ValueError, TypeError):
                severity = 'High' if any(w in str(name).lower() for w in ['injection', 'rce', 'overflow', 'bypass']) else 'Low'

        # 3. Confidence
        conf_raw = str(alert.get('confidence', alert.get('confidenceDesc', conf_from_desc or '2'))).lower()
        confidence = CONFIDENCE_MAP.get(conf_raw, 'Medium')
        if not confidence or confidence == 'Medium':
            if 'high' in conf_raw: confidence = 'High'
            elif 'low' in conf_raw: confidence = 'Low'
            elif 'false positive' in conf_raw: confidence = 'False Positive'

        # 4. Instances / Endpoint / Parameter / Evidence
        instances = alert.get('instances', alert.get('occurrences', []))
        if isinstance(instances, dict):
            instances = instances.get('instance') or [instances]

        url = ''
        method = 'GET'
        parameter = ''
        evidence = ''

        if isinstance(instances, list) and len(instances) > 0 and isinstance(instances[0], dict):
            first = instances[0]
            url = first.get('uri') or first.get('url') or ''
            method = first.get('method') or 'GET'
            parameter = first.get('param') or first.get('parameter') or ''
            evidence = first.get('evidence') or first.get('attack') or first.get('payload') or ''

        if not url:
            url = alert.get('url') or alert.get('uri') or alert.get('matched-at') or alert.get('host') or alert.get('endpoint') or ''
        if not parameter:
            parameter = alert.get('param') or alert.get('parameter') or alert.get('input') or ''
        if not evidence:
            evidence = alert.get('evidence') or alert.get('attack') or alert.get('payload') or str(alert.get('extracted-results', ''))
        if not method or method == 'GET':
            method = alert.get('method') or 'GET'

        # 5. CWE Classification
        cwe_raw = alert.get('cweid') or alert.get('cweId') or alert.get('cwe') or alert.get('cwe_id') or ''
        if not cwe_raw and isinstance(alert.get('classification'), dict):
            cwe_raw = alert['classification'].get('cwe-id', '')
        if not cwe_raw and isinstance(info.get('classification'), dict):
            cwe_raw = info['classification'].get('cwe-id', '')

        if cwe_raw and str(cwe_raw).strip() not in ('', '-1', '0', 'None', 'null'):
            cwe_clean = str(cwe_raw).replace('CWE-', '').strip()
            cwe_id = f"CWE-{cwe_clean}"
        else:
            cwe_id = 'N/A'

        # Description and solution
        desc = (
            alert.get('desc') or
            alert.get('description') or
            info.get('description') or
            alert.get('detail') or
            alert.get('summary') or
            alert.get('issueBackground') or
            ''
        )
        sol = (
            alert.get('solution') or
            alert.get('remediation') or
            alert.get('recommendation') or
            info.get('remediation') or
            alert.get('remediationBackground') or
            ''
        )

        return NormalizedFinding(
            name=str(name).strip(),
            description=str(desc).strip(),
            severity=severity,
            confidence=confidence,
            url=str(url).strip(),
            method=str(method).upper().strip() or 'GET',
            parameter=str(parameter).strip(),
            evidence=str(evidence).strip(),
            solution=str(sol).strip(),
            reference=str(alert.get('reference') or alert.get('references') or info.get('reference') or '').strip(),
            cwe_id=cwe_id,
            plugin_id=str(alert.get('pluginid') or alert.get('pluginId') or alert.get('id') or '').strip(),
            alert_ref=str(alert.get('alertRef') or alert.get('alert_ref') or '').strip(),
            instances=instances if isinstance(instances, list) else [],
        )


# Singleton
zap_parser = ZAPParser()
