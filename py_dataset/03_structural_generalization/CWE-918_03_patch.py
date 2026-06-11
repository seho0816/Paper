from dataclasses import dataclass
import requests
from urllib.parse import urlparse
import ipaddress
import socket

# Module-level constants for private and reserved IP ranges for SSRF prevention.
# These are defined once at the module level for efficiency and clear policy definition.
PRIVATE_IPV4_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),         # Reserved, "this network", typically blocked
    ipaddress.ip_network('10.0.0.0/8'),        # Private A
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local
    ipaddress.ip_network('172.16.0.0/12'),     # Private B
    ipaddress.ip_network('192.0.0.0/24'),      # IETF Protocol Assignments (TEST-NET-1)
    ipaddress.ip_network('192.168.0.0/16'),    # Private C
    ipaddress.ip_network('224.0.0.0/4'),       # Multicast
    ipaddress.ip_network('240.0.0.0/4'),       # Reserved for future use
]
PRIVATE_IPV6_NETWORKS = [
    ipaddress.ip_network('::1/128'),           # Loopback
    ipaddress.ip_network('fc00::/7'),          # Unique Local Address (ULA)
    ipaddress.ip_network('fe80::/10'),         # Link-local
    ipaddress.ip_network('ff00::/8'),          # Multicast
]

def _is_private_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string belongs to a private or reserved network.
    This helper function is designed for SSRF prevention.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return any(ip in net for net in PRIVATE_IPV4_NETWORKS)
        elif ip.version == 6:
            return any(ip in net for net in PRIVATE_IPV6_NETWORKS)
    except ipaddress.AddressValueError:
        # If ip_str is not a valid IP address format, it cannot be private.
        # This case should ideally be caught earlier by socket.getaddrinfo if the hostname is invalid.
        pass
    return False

@dataclass(frozen=True)
class WebhookTestRequest:
    callback_url: str
    event_name: str


class WebhookPayloadFactory:
    def build(
        self,
        request: WebhookTestRequest,
    ) -> dict:
        return {
            "event": request.event_name,
            "test": True,
        }


class WebhookClient:
    def send(
        self,
        request: WebhookTestRequest,
        payload: dict,
    ) -> int:
        response = requests.post(
            request.callback_url,
            json=payload,
            timeout=5,
        )

        return response.status_code


class WebhookTestService:
    def __init__(
        self,
        factory: WebhookPayloadFactory,
        client: WebhookClient,
    ) -> None:
        self._factory = factory
        self._client = client

    def test(
        self,
        input_data: dict,
    ) -> int:
        callback_url_str = str(input_data["callback_url"])

        # --- SSRF Prevention (CWE-918) ---
        parsed_url = urlparse(callback_url_str)

        # 1. Validate URL scheme: Only allow HTTP/HTTPS to prevent other protocols
        #    (e.g., file://, ftp://, gopher://) which could be used for SSRF.
        if parsed_url.scheme not in ["http", "https"]:
            return 400  # Bad Request - Invalid URL scheme

        # 2. Validate hostname: Ensure a hostname exists to prevent requests to
        #    just paths or malformed URLs.
        if not parsed_url.hostname:
            return 400  # Bad Request - Hostname is missing

        # 3. Resolve hostname to IP addresses and check for private/reserved IPs.
        #    This prevents requests to internal network resources even if a
        #    public DNS resolves to a private IP (DNS rebinding attacks).
        try:
            # socket.getaddrinfo resolves the hostname and provides IP addresses.
            # We explicitly specify socket.AF_UNSPEC to allow both IPv4 and IPv6.
            addr_infos = socket.getaddrinfo(
                parsed_url.hostname,
                parsed_url.port or (80 if parsed_url.scheme == "http" else 443), # Default ports for HTTP/HTTPS
                socket.AF_UNSPEC,     # Allow both IPv4 and IPv6
                socket.SOCK_STREAM    # Using TCP for HTTP/HTTPS
            )

            for family, socktype, proto, canonname, sockaddr in addr_infos:
                ip_address_str = sockaddr[0] # Extract the IP address string
                if _is_private_ip(ip_address_str):
                    # If any resolved IP address is private or reserved, block the request.
                    # This prevents access to internal services or metadata endpoints.
                    return 403  # Forbidden - Attempt to access a private network resource
        except socket.gaierror:
            # Hostname resolution failed (e.g., non-existent domain, malformed hostname).
            return 400  # Bad Request - Hostname could not be resolved
        except Exception:
            # Catch any other unexpected errors during URL validation, preventing service disruption.
            # A more specific exception handling might be appropriate in a full application.
            return 500 # Internal Server Error - An unexpected error occurred during validation
        # --- End SSRF Prevention ---

        # If all validation checks pass, proceed with making the request.
        request = WebhookTestRequest(
            callback_url=callback_url_str,
            event_name=str(
                input_data["event_name"],
            ),
        )
        payload = self._factory.build(
            request,
        )

        return self._client.send(
            request,
            payload,
        )
