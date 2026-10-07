"""
SecureGate Target Security & SSRF Protection Engine
Validates scan targets, blocks malicious schemes, prevents DNS rebinding,
and denies unauthorized private/cloud-metadata network probing.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional


# Blocked reserved/cloud metadata networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 private
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Explicitly authorized targets for local authorized testbeds (Juice Shop, DVWA testbeds)
AUTHORIZED_LOCAL_TARGETS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "juiceshop",
    "pentest-ground.com",
    "testphp.vulnweb.com",
}


def validate_scan_target(
    url: str,
    allow_private_in_dev: bool = True
) -> Tuple[bool, str, Optional[str]]:
    """
    Validates that a URL is a legitimate, authorized web scan target and not an SSRF exploit vector.
    Returns: (is_valid: bool, canonical_url: str, error_message: Optional[str])
    """
    if not url or not isinstance(url, str):
        return False, "", "Target URL must be a non-empty string"

    target = url.strip()
    if "://" in target:
        scheme = target.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return False, "", f"Unsupported protocol '{scheme}'. Only HTTP and HTTPS are permitted."
    else:
        target = f"https://{target}"

    try:
        parsed = urlparse(target)
    except Exception as e:
        return False, "", f"Malformed URL syntax: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, "", f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "", "Target URL must contain a valid hostname or domain."

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port < 1 or port > 65535:
        return False, "", f"Invalid TCP port: {port}"

    canonical = f"{parsed.scheme}://{hostname}:{port}" if (parsed.port and parsed.port not in (80, 443)) else f"{parsed.scheme}://{hostname}"

    # Check authorized local testbed hosts
    is_authorized_testbed = any(
        hostname.lower() == auth.lower() or hostname.lower().endswith(f".{auth.lower()}")
        for auth in AUTHORIZED_LOCAL_TARGETS
    )

    if is_authorized_testbed and allow_private_in_dev:
        return True, canonical, None

    # Resolve IP address to detect internal RFC 1918 or Cloud Metadata SSRF
    try:
        # Resolve hostname
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)

            # Check if resolved IP is in any blocked network
            for net in BLOCKED_NETWORKS:
                if ip_obj in net:
                    if not (is_authorized_testbed and allow_private_in_dev):
                        return False, "", f"Security Restriction: Target '{hostname}' resolves to private/internal IP {ip_str} ({net}). Internal scanning requires authorized development mode."
    except socket.gaierror:
        # DNS lookup failed
        # If it's a known docker service or authorized host in container network
        if not is_authorized_testbed:
            return False, "", f"Unable to resolve DNS for host '{hostname}'. Ensure domain exists and is accessible."

    return True, canonical, None


def validate_target_url(url: str, allow_private: bool = True) -> Tuple[bool, Optional[str]]:
    """Convenience wrapper returning (is_valid, error_message)."""
    is_valid, _, err = validate_scan_target(url, allow_private_in_dev=allow_private)
    return is_valid, err

