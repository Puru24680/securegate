"""
Vulnerability Fingerprinting & Lifecycle Engine
Generates immutable SHA-256 fingerprints to deduplicate vulnerabilities
across repeated scans, track first_seen/last_seen dates, and manage regression states.
"""
import hashlib
import re
from urllib.parse import urlparse


def normalize_endpoint_path(raw_url: str) -> str:
    """Extract and normalize the endpoint path, stripping query strings and volatile IDs."""
    if not raw_url:
        return "/"
    try:
        parsed = urlparse(raw_url)
        path = parsed.path or "/"
        # Normalize dynamic numeric IDs (e.g. /products/42 -> /products/{id})
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        return path.lower().rstrip("/") or "/"
    except Exception:
        return str(raw_url).lower().split("?")[0].rstrip("/") or "/"


def compute_finding_fingerprint(
    project_id: int,
    cwe_id: str,
    url: str,
    parameter: str,
    plugin_id: str,
    finding_name: str = ""
) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a vulnerability.
    Fingerprint identity: (project_id, cwe_id or plugin_id or normalized_title, normalized_path, parameter)
    """
    norm_path = normalize_endpoint_path(url)
    norm_param = (parameter or "").strip().lower()
    norm_cwe = (cwe_id or "N/A").strip().upper().replace("CWE-", "")
    norm_plugin = (plugin_id or "").strip().lower()
    norm_title = re.sub(r"[^a-z0-9]", "", finding_name.lower()) if finding_name else ""

    identity_str = f"proj:{project_id}|cwe:{norm_cwe}|plugin:{norm_plugin}|title:{norm_title}|path:{norm_path}|param:{norm_param}"
    return hashlib.sha256(identity_str.encode("utf-8")).hexdigest()
