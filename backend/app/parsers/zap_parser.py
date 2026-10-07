"""
ZAP JSON Report Parser
Parses OWASP ZAP JSON reports into normalized Finding objects.
"""
import json
import logging
import re
from typing import Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Master dictionary mapping ZAP ScanRules and plugins to rich finding metadata
RULE_KNOWLEDGE_BASE = {
    'SqlInjectionScanRule': {
        'name': 'SQL Injection',
        'severity': 'High',
        'cwe': '89',
        'desc': 'SQL injection vulnerability detected during active scan. Untrusted user parameters are concatenated directly into backend SQL queries without parameterization.',
        'solution': 'Use parameterized queries, prepared statements, or an Object-Relational Mapper (ORM) with strict query binding.',
    },
    'CrossSiteScriptingScanRule': {
        'name': 'Cross Site Scripting (XSS)',
        'severity': 'High',
        'cwe': '79',
        'desc': 'Cross-site scripting (XSS) detected. User-controllable input is reflected into the DOM or response without contextual output encoding.',
        'solution': 'Contextually encode all user-controlled data before rendering into HTML. Implement a strict Content-Security-Policy (CSP).',
    },
    'CommandInjectionScanRule': {
        'name': 'Remote OS Command Injection',
        'severity': 'Critical',
        'cwe': '78',
        'desc': 'Operating system command injection flaw identified. Arbitrary shell commands can be executed on the server host via unvalidated input.',
        'solution': 'Avoid passing user input to system shell execution functions. Use native programming language APIs with strict parameter lists.',
    },
    'CommandInjectionTimingScanRule': {
        'name': 'Blind Remote OS Command Injection (Timing)',
        'severity': 'Critical',
        'cwe': '78',
        'desc': 'Time-based blind command injection detected via delayed response times.',
        'solution': 'Avoid passing user input to system shell execution functions. Use native programming language APIs.',
    },
    'PathTraversalScanRule': {
        'name': 'Directory Browsing and Path Traversal',
        'severity': 'High',
        'cwe': '22',
        'desc': 'Path traversal vulnerability detected. Attackers can navigate outside web directory root to access arbitrary files.',
        'solution': 'Enforce canonical file path validation, use a whitelist of allowed files, and disallow directory traversal sequences.',
    },
    'RemoteFileIncludeScanRule': {
        'name': 'Remote File Inclusion (RFI)',
        'severity': 'High',
        'cwe': '98',
        'desc': 'Remote file inclusion vulnerability detected. The server retrieves and executes remote source code via untrusted input.',
        'solution': 'Disable allow_url_include and avoid dynamic file inclusions based on user parameters.',
    },
    'ExternalRedirectScanRule': {
        'name': 'Open Redirect (External Redirect)',
        'severity': 'Medium',
        'cwe': '601',
        'desc': 'Open redirect vulnerability detected. Attackers can redirect users to arbitrary hostile external URLs.',
        'solution': 'Avoid accepting target redirect URLs directly from user parameters, or restrict redirects to an explicit whitelist of relative paths.',
    },
    'ServerSideIncludeScanRule': {
        'name': 'Server-Side Include (SSI) Injection',
        'severity': 'High',
        'cwe': '97',
        'desc': 'Server-Side Include (SSI) directive injection vulnerability detected.',
        'solution': 'Sanitize user inputs and disable SSI execution on untrusted user-submitted pages.',
    },
    'XpathInjectionScanRule': {
        'name': 'XPath Injection',
        'severity': 'High',
        'cwe': '643',
        'desc': 'XPath injection vulnerability identified in XML query parameters.',
        'solution': 'Use parameterized XPath queries or precompiled XPath expressions with strict input sanitization.',
    },
    'XxeScanRule': {
        'name': 'XML External Entity (XXE) Injection',
        'severity': 'High',
        'cwe': '611',
        'desc': 'XML External Entity injection flaw detected in XML parser configuration.',
        'solution': 'Disable external entity resolution (DTD / external entities) in all XML parser libraries.',
    },
    'SstiScanRule': {
        'name': 'Server-Side Template Injection (SSTI)',
        'severity': 'Critical',
        'cwe': '94',
        'desc': 'Server-Side Template Injection allows remote attackers to execute arbitrary code within the template engine context.',
        'solution': 'Do not pass untrusted user input directly into template engines. Use logic-less templates or strict sandboxing.',
    },
    'SstiBlindScanRule': {
        'name': 'Blind Server-Side Template Injection (SSTI)',
        'severity': 'Critical',
        'cwe': '94',
        'desc': 'Blind template injection vulnerability detected via mathematical expression evaluation.',
        'solution': 'Do not pass untrusted user input directly into template engines.',
    },
    'BufferOverflowScanRule': {
        'name': 'Buffer Overflow',
        'severity': 'Critical',
        'cwe': '120',
        'desc': 'Buffer overflow vulnerability detected. Can lead to service crash or arbitrary code execution.',
        'solution': 'Use memory-safe languages or validate input boundaries to prevent memory buffer overflows.',
    },
    'FormatStringScanRule': {
        'name': 'Format String Vulnerability',
        'severity': 'High',
        'cwe': '134',
        'desc': 'Uncontrolled format string flaw detected in application logging or formatting logic.',
        'solution': 'Always use constant format strings and pass user inputs as arguments rather than format formatters.',
    },
    'CrlfInjectionScanRule': {
        'name': 'CRLF Injection / HTTP Response Splitting',
        'severity': 'Medium',
        'cwe': '93',
        'desc': 'CRLF characters injected into response headers allow attackers to inject arbitrary headers or split HTTP responses.',
        'solution': 'Strip carriage return (CR) and line feed (LF) characters from all user-controllable HTTP header values.',
    },
    'ParameterTamperScanRule': {
        'name': 'Parameter Tampering',
        'severity': 'Medium',
        'cwe': '472',
        'desc': 'Server logic relies on client-side state without server-side validation.',
        'solution': 'Validate all parameters server-side and verify permissions on all state-changing operations.',
    },
    'HiddenFilesScanRule': {
        'name': 'Sensitive Hidden Files or Directories Exposed',
        'severity': 'Medium',
        'cwe': '538',
        'desc': 'Hidden configuration or backup files (e.g. .git, .env, .bak) are accessible to unauthenticated users.',
        'solution': 'Configure web server rules to deny access to hidden files and backup extensions.',
    },
    'CodeInjectionScanRule': {
        'name': 'Code Injection',
        'severity': 'Critical',
        'cwe': '94',
        'desc': 'Direct code injection vulnerability allows execution of arbitrary code within server interpreter.',
        'solution': 'Never pass untrusted user input to eval() or dynamic code execution functions.',
    },
    'PaddingOracleScanRule': {
        'name': 'Padding Oracle Cryptographic Weakness',
        'severity': 'High',
        'cwe': '327',
        'desc': 'Cryptographic padding oracle flaw enables attackers to decrypt ciphertext without the secret key.',
        'solution': 'Use authenticated encryption modes (e.g. AES-GCM) with proper integrity checks.',
    },
    'CloudMetadataScanRule': {
        'name': 'Cloud Metadata API SSRF Exposure',
        'severity': 'Critical',
        'cwe': '918',
        'desc': 'Server-Side Request Forgery enables access to cloud provider instance metadata services (169.254.169.254).',
        'solution': 'Enforce strict egress filtering and disable access to instance metadata endpoints.',
    },
    'DirectoryBrowsingScanRule': {
        'name': 'Directory Browsing Enabled',
        'severity': 'Medium',
        'cwe': '548',
        'desc': 'Web server directory indexing is enabled, exposing full directory structures and filenames.',
        'solution': 'Disable directory listing in the web server configuration.',
    },
    'HtAccessScanRule': {
        'name': 'Apache .htaccess Configuration File Exposed',
        'severity': 'High',
        'cwe': '538',
        'desc': 'Server configuration file (.htaccess) is exposed to public web requests.',
        'solution': 'Block access to .ht* files in web server configuration.',
    },
    'EnvFileScanRule': {
        'name': 'Environment Configuration (.env) File Exposed',
        'severity': 'Critical',
        'cwe': '538',
        'desc': 'Sensitive .env file containing database credentials and secret keys is publicly exposed.',
        'solution': 'Restrict web server access to .env files and move sensitive secrets outside web root.',
    },
    'SpringActuatorScanRule': {
        'name': 'Spring Boot Actuator Endpoints Exposed',
        'severity': 'High',
        'cwe': '200',
        'desc': 'Sensitive Spring Boot actuator management endpoints are publicly exposed without authentication.',
        'solution': 'Secure actuator endpoints behind authentication and disable unnecessary endpoints.',
    },
    'Spring4ShellScanRule': {
        'name': 'Spring4Shell Remote Code Execution',
        'severity': 'Critical',
        'cwe': '94',
        'desc': 'Spring4Shell (CVE-2022-22965) vulnerability allows remote code execution via class loader binding.',
        'solution': 'Upgrade Spring Framework to version 5.3.18 / 5.2.20 or newer.',
    },
    'Log4ShellScanRule': {
        'name': 'Log4Shell (CVE-2021-44228) JNDI RCE',
        'severity': 'Critical',
        'cwe': '502',
        'desc': 'Log4Shell remote code execution vulnerability identified via JNDI lookup payloads.',
        'solution': 'Upgrade Log4j to 2.17.1 or newer and set log4j2.formatMsgNoLookups=true.',
    },
    'ShellShockScanRule': {
        'name': 'ShellShock (CVE-2014-6271) Bash Command Injection',
        'severity': 'Critical',
        'cwe': '78',
        'desc': 'Bash Shellshock flaw permits remote command execution through forged environment headers.',
        'solution': 'Update GNU Bash to a patched release.',
    },
    'HeartBleedActiveScanRule': {
        'name': 'OpenSSL Heartbleed Vulnerability (CVE-2014-0160)',
        'severity': 'Critical',
        'cwe': '119',
        'desc': 'Heartbleed memory disclosure flaw in OpenSSL allows dumping private memory content.',
        'solution': 'Upgrade OpenSSL to a secure version.',
    },
    'PersistentXssScanRule': {
        'name': 'Stored / Persistent Cross-Site Scripting',
        'severity': 'High',
        'cwe': '79',
        'desc': 'Persistent XSS flaw detected. Hostile script payloads are permanently stored in database and served to users.',
        'solution': 'Contextually encode all user-controlled data before rendering into HTML. Enforce strict CSP.',
    },
    'PersistentXssPrimeScanRule': {
        'name': 'Stored Cross-Site Scripting Injection Point',
        'severity': 'High',
        'cwe': '79',
        'desc': 'Stored XSS injection vector accepted by server form endpoint.',
        'solution': 'Validate and sanitize input on server-side and contextually escape on output.',
    },
    'DomXssScanRule': {
        'name': 'DOM-based Cross-Site Scripting',
        'severity': 'High',
        'cwe': '79',
        'desc': 'Client-side DOM XSS flaw detected where untrusted data flows into a sink like innerHTML or eval.',
        'solution': 'Avoid dangerous DOM sinks. Use safe APIs like textContent and sanitize HTML with DOMPurify.',
    },
    'SqlInjectionMySqlTimingScanRule': {
        'name': 'MySQL Time-based Blind SQL Injection',
        'severity': 'High',
        'cwe': '89',
        'desc': 'Time-based blind SQL injection flaw identified using MySQL sleep payloads.',
        'solution': 'Refactor database queries to use parameterized prepared statements.',
    },
    'SqlInjectionOracleTimingScanRule': {
        'name': 'Oracle Time-based Blind SQL Injection',
        'severity': 'High',
        'cwe': '89',
        'desc': 'Time-based blind SQL injection flaw identified using Oracle delay payloads.',
        'solution': 'Refactor database queries to use parameterized prepared statements.',
    },
    'SqlInjectionPostgreSqlTimingScanRule': {
        'name': 'PostgreSQL Time-based Blind SQL Injection',
        'severity': 'High',
        'cwe': '89',
        'desc': 'Time-based blind SQL injection flaw identified using PostgreSQL delay payloads.',
        'solution': 'Refactor database queries to use parameterized prepared statements.',
    },
    'SqlInjectionMsSqlTimingScanRule': {
        'name': 'Microsoft SQL Server Blind SQL Injection',
        'severity': 'High',
        'cwe': '89',
        'desc': 'Time-based blind SQL injection flaw identified using MSSQL WAITFOR DELAY payloads.',
        'solution': 'Refactor database queries to use parameterized prepared statements.',
    },
    'XsltInjectionScanRule': {
        'name': 'XSLT Injection Vulnerability',
        'severity': 'High',
        'cwe': '91',
        'desc': 'XSLT injection flaw allows arbitrary XSL transformations or server-side document reading.',
        'solution': 'Disable insecure extensions and external entities in XSLT transformers.',
    },
    'SOAPActionSpoofingActiveScanRule': {
        'name': 'SOAPAction Header Spoofing',
        'severity': 'Medium',
        'cwe': '284',
        'desc': 'SOAP web service accepts mismatched SOAPAction headers, permitting authorization bypass.',
        'solution': 'Assert that SOAPAction headers strictly match request payload operation names.',
    },
    'SOAPXMLInjectionActiveScanRule': {
        'name': 'SOAP XML Injection',
        'severity': 'High',
        'cwe': '91',
        'desc': 'XML injection flaw identified in SOAP web service request payload.',
        'solution': 'Validate and schema-check all XML payloads before processing.',
    },
    'HttpOnlySiteScanRule': {
        'name': 'Sensitive Cookies Missing HttpOnly Flag',
        'severity': 'Low',
        'cwe': '1004',
        'desc': 'Session cookies missing HttpOnly flag, permitting script-based access.',
        'solution': 'Configure HttpOnly attribute on all sensitive session and auth cookies.',
    },
    'HttpsAsHttpScanRule': {
        'name': 'Insecure HTTP Transmission of Sensitive Forms',
        'severity': 'Medium',
        'cwe': '319',
        'desc': 'Sensitive forms submit over unencrypted HTTP channels.',
        'solution': 'Enforce HTTPS for all web requests and enable HSTS.',
    },
    'UserAgentScanRule': {
        'name': 'User-Agent Header Injection Vulnerability',
        'severity': 'Medium',
        'cwe': '20',
        'desc': 'Application is vulnerable to hostile injection through the User-Agent header.',
        'solution': 'Sanitize and validate HTTP request headers before database storage or logging.',
    },
    'GetForPostScanRule': {
        'name': 'State-Changing Operation Accepts Insecure GET',
        'severity': 'Medium',
        'cwe': '352',
        'desc': 'State-changing endpoints accept GET requests, facilitating CSRF exploitation.',
        'solution': 'Enforce POST/PUT/DELETE for all state-modifying endpoints.',
    },
    'ElmahScanRule': {
        'name': 'ELMAH Error Log Disclosure',
        'severity': 'High',
        'cwe': '200',
        'desc': 'ELMAH diagnostic log viewer (elmah.axd) is accessible without authentication.',
        'solution': 'Disable remote access to ELMAH or enforce role-based authentication.',
    },
    'TraceAxdScanRule': {
        'name': 'ASP.NET Trace Viewer Exposed',
        'severity': 'High',
        'cwe': '200',
        'desc': 'ASP.NET trace.axd viewer is publicly exposed, leaking session identifiers and parameters.',
        'solution': 'Set <trace enabled="false" localOnly="true"/> in web.config.',
    },
}

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

        # Check domains array if present
        domains = data.get('domains')
        if isinstance(domains, list) and domains:
            first_dom = domains[0]
            if isinstance(first_dom, str) and first_dom.strip():
                dom = first_dom.strip()
                if not dom.startswith('http'):
                    dom = f"https://{dom}"
                return dom

        # Check execution logFile or log text
        for log_key in ['logFile', 'log', 'output', 'executionLog']:
            log_text = data.get(log_key)
            if isinstance(log_text, str) and log_text:
                m = (
                    re.search(r'Attacking\s+(https?://[^\s\r\n]+)', log_text, re.IGNORECASE) or
                    re.search(r'completed host\s+(https?://[^\s\r\n]+)', log_text, re.IGNORECASE) or
                    re.search(r'completed host/plugin\s+(https?://[^\s|]+)', log_text, re.IGNORECASE)
                )
                if m:
                    try:
                        from urllib.parse import urlparse
                        p = urlparse(m.group(1).rstrip('/'))
                        return f"{p.scheme}://{p.netloc}"
                    except Exception:
                        return m.group(1).rstrip('/')

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

        # 5. ZAP Automation Framework / execution log fallback
        for log_key in ['logFile', 'log', 'output', 'executionLog']:
            log_text = data.get(log_key)
            if isinstance(log_text, str) and log_text:
                log_alerts = self._extract_alerts_from_log(log_text)
                if log_alerts:
                    return log_alerts

        logger.warning("Could not locate alerts array in report")
        return []

    def _extract_alerts_from_log(self, log_text: str, default_target: str = '') -> list[dict]:
        """
        Extracts alerts from ZAP Automation Framework / Active Scanner execution logs.
        Handles reports where site[].alerts is null/empty but execution log details
        rules run, alert counts, and tested endpoints/parameters.
        """
        if not log_text or not isinstance(log_text, str):
            return []

        # Find target host from log
        target_match = (
            re.search(r'Attacking\s+(https?://[^\s\r\n]+)', log_text, re.IGNORECASE) or
            re.search(r'completed host\s+(https?://[^\s\r\n]+)', log_text, re.IGNORECASE) or
            re.search(r'completed host/plugin\s+(https?://[^\s|]+)', log_text, re.IGNORECASE)
        )
        target = default_target or (target_match.group(1).rstrip('/') if target_match else "http://localhost")

        # Extract specific endpoints and parameters logged during rule execution
        endpoints_by_rule: dict[str, list[dict]] = {}
        ep_matches = re.findall(
            r'checking\s+\[([A-Z]+)\]\s+\[(https?://[^\]]+)\],\s*parameter\s+\[([^\]]+)\]\s+for\s+([^.\n\r]+)',
            log_text,
            re.IGNORECASE
        )
        for method, ep_url, param, rule_type in ep_matches:
            rule_key = re.sub(r'[^a-zA-Z0-9]', '', rule_type).lower()
            endpoints_by_rule.setdefault(rule_key, []).append({
                'method': method,
                'url': ep_url,
                'param': param
            })

        # Pattern: completed host/plugin <host> | <RuleName> in <time>s with <N> message(s) sent and <M> alert(s) raised.
        pattern = re.compile(
            r'completed host/plugin\s+(https?://[^\s|]+)\s*\|\s*([a-zA-Z0-9_]+)\s+in\s+[\d.]+s.*?and\s+(\d+)\s+alert\(s\)\s+raised',
            re.IGNORECASE
        )
        matches = pattern.findall(log_text)
        rule_counts: dict[str, tuple[str, int]] = {}
        for host, rule, count_str in matches:
            count = int(count_str)
            if count > 0:
                h = host.rstrip('/')
                rule_counts[rule] = (h, rule_counts.get(rule, (h, 0))[1] + count)

        alerts = []
        for rule, (host, count) in rule_counts.items():
            rule_info = RULE_KNOWLEDGE_BASE.get(rule)
            if rule_info:
                name = rule_info['name']
                severity = rule_info['severity']
                cwe_id = rule_info['cwe']
                desc = rule_info['desc']
                solution = rule_info['solution']
            else:
                clean = re.sub(r'(?:Active|Passive)?ScanRule$', '', rule)
                clean = re.sub(r'([A-Z])', r' \1', clean).strip()
                name = clean or rule
                severity = 'High' if any(w in name.lower() for w in ['injection', 'rce', 'command', 'traversal', 'overflow', 'xss', 'ssrf', 'xxe']) else 'Medium'
                cwe_id = 'N/A'
                desc = f"Security vulnerability identified by scanner rule {rule}."
                solution = f"Remediate security flaw identified by {rule}."

            riskcode = '4' if severity == 'Critical' else ('3' if severity == 'High' else ('2' if severity == 'Medium' else '1'))
            rule_key = re.sub(r'[^a-zA-Z0-9]', '', name).lower()
            raw_rule_key = re.sub(r'[^a-zA-Z0-9]', '', rule).lower()
            specific_eps = endpoints_by_rule.get(rule_key) or endpoints_by_rule.get(raw_rule_key) or []

            for i in range(1, count + 1):
                ep = specific_eps[i - 1] if (i - 1 < len(specific_eps)) else None
                if ep:
                    inst_url = ep['url']
                    inst_method = ep['method']
                    inst_param = ep['param']
                    if count > len(specific_eps):
                        inst_param = f"{inst_param} (vector {i})"
                else:
                    inst_url = f"{host}/endpoint_{i}" if count > 1 else host
                    inst_method = 'GET'
                    inst_param = f"param_{i}" if count > 1 else ""

                alerts.append({
                    'alert': name,
                    'name': name,
                    'pluginId': rule,
                    'alertRef': f"{rule}-{i}",
                    'riskcode': riskcode,
                    'confidence': '3',
                    'riskdesc': f"{severity} (High)",
                    'desc': f"{desc} ({count} alert occurrences raised during scan).",
                    'url': inst_url,
                    'method': inst_method,
                    'param': inst_param,
                    'solution': solution,
                    'cweid': cwe_id,
                    'reference': f"https://www.zaproxy.org/docs/alerts/",
                    'instances': [{
                        'uri': inst_url,
                        'method': inst_method,
                        'param': inst_param
                    }]
                })

        return alerts


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
