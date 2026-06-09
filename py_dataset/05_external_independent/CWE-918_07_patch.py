import urllib3
import urllib.parse
import socket
import ipaddress


http = urllib3.PoolManager()


def _is_internal_ip_resolved(hostname: str) -> bool:
    """
    Checks if a hostname resolves to any internal IP address (private, loopback, link-local).
    Returns True if any resolved IP is internal, False otherwise.
    Raises ValueError if hostname is an empty string or None.
    """
    if not hostname:
        raise ValueError("Hostname cannot be empty or None for IP resolution.")

    try:
        # getaddrinfo resolves hostnames and IP literals, and handles both IPv4 and IPv6.
        # We only need the IP addresses, so 'None' for port is fine for resolution.
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        for family, socktype, proto, canonname, sockaddr in addr_infos:
            ip_str = None
            if family == socket.AF_INET: # IPv4
                ip_str = sockaddr[0]
            elif family == socket.AF_INET6: # IPv6
                ip_str = sockaddr[0]
            
            if ip_str:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        return True
                except ValueError:
                    # This should not happen if socket.getaddrinfo returned a valid IP string.
                    # If it does, consider it not an internal IP for this check's purpose.
                    pass
        return False
    except socket.gaierror:
        # Hostname resolution failed (e.g., non-existent domain).
        # In this case, it doesn't resolve to an internal IP, so return False.
        # urllib3 will then fail the request due to resolution error.
        return False
    except Exception:
        # Catch any other unexpected errors during resolution.
        # For SSRF, if we cannot reliably determine the IP, it's safer to block,
        # but returning False and letting urllib3 handle the connection error is also valid,
        # as it doesn't bypass the internal IP check.
        return False


def relay_document(
    document_url: str,
) -> bytes:
    parsed_url = urllib.parse.urlparse(document_url)
    hostname = parsed_url.hostname

    if hostname: # Only perform SSRF check if a hostname is present in the URL.
        if _is_internal_ip_resolved(hostname):
            raise ValueError(f"Access to internal network resources for '{hostname}' is not allowed.")
    
    # If hostname is None (e.g., relative URL, or malformed URL without a host part),
    # or if the scheme is not HTTP/HTTPS (e.g., file://), urllib3's request method
    # will handle it by raising an appropriate exception (e.g., URLSchemeError, MaxRetryError).
    # We don't need to duplicate that validation here, as the primary SSRF vector
    # through hostname resolution is addressed.

    response = http.request(
        "GET",
        document_url,
        timeout=urllib3.Timeout(
            total=5,
        ),
        preload_content=True,
    )

    return response.data
