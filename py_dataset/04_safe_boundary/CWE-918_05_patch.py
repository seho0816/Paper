import re
import requests
import ipaddress
import socket
from urllib.parse import urlparse

USER_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,40}$"
)

DIRECTORY_API_BASE = (
    "https://directory.example.com"
)


def load_user_profile(
    user_id: str,
) -> dict:
    if not USER_ID_PATTERN.fullmatch(
        user_id,
    ):
        raise ValueError(
            "invalid user id"
        )

    # CWE-918 mitigation: Validate the target hostname to prevent Server-Side Request Forgery (SSRF)
    # This check ensures that DIRECTORY_API_BASE does not resolve to a private or loopback IP address,
    # which could happen via DNS manipulation (e.g., DNS rebinding, /etc/hosts file compromise).
    parsed_base_url = urlparse(DIRECTORY_API_BASE)
    if not parsed_base_url.hostname:
        raise ValueError("DIRECTORY_API_BASE has no valid hostname")

    try:
        # Resolve the hostname to IP addresses. socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        resolved_ips = socket.gethostbyname_ex(parsed_base_url.hostname)[2]
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname for {parsed_base_url.hostname}")

    # Check if any of the resolved IP addresses are private or loopback
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                raise ValueError(
                    f"Resolved IP {ip_str} for {parsed_base_url.hostname} is a private or loopback address. "
                    "Potential Server-Side Request Forgery (SSRF)."
                )
        except ValueError:
            # If ip_str is not a valid IP address format, skip or log an error.
            # In a robust system, this might warrant a different error handling.
            continue

    response = requests.get(
        f"{DIRECTORY_API_BASE}/users/{user_id}",
        timeout=5,
        allow_redirects=False,
    )
    response.raise_for_status()

    return response.json()
