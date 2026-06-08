import ipaddress
import socket
from urllib.request import urlopen
from urllib.parse import urlparse
from flask import request, abort

def fetch_url():
    target_url = request.args.get("url")

    if not target_url:
        abort(400, "URL parameter is missing.")

    try:
        parsed_url = urlparse(target_url)

        # 1. Validate scheme: Only allow HTTP and HTTPS
        if parsed_url.scheme not in ("http", "https"):
            abort(400, "Only HTTP and HTTPS schemes are allowed.")

        # 2. Validate hostname presence
        if not parsed_url.hostname:
            abort(400, "Invalid URL: hostname is missing.")

        # 3. Resolve hostname to IP addresses and validate them
        resolved_ips = []
        try:
            # socket.getaddrinfo resolves hostname to IP addresses (IPv4 and IPv6)
            # and is more robust than gethostbyname.
            # It returns a list of 5-tuples: (family, socktype, proto, canonname, sockaddr).
            # sockaddr is a tuple (ip_address_string, port) for IPv4 or (ip_address_string, port, flowinfo, scopeid) for IPv6.
            # We use parsed_url.port or default to 80 if not specified.
            addr_info = socket.getaddrinfo(parsed_url.hostname, parsed_url.port or 80, proto=socket.IPPROTO_TCP)
            for family, socktype, proto, canonname, sockaddr in addr_info:
                ip_str = sockaddr[0]
                resolved_ips.append(ip_str)
        except socket.gaierror:
            abort(400, "Could not resolve hostname.")
        except Exception:
            # Catch other potential errors during DNS resolution, e.g., if service/port is malformed.
            abort(500, "Error during hostname resolution.")

        # Define forbidden IP ranges (CIDRs) to prevent access to internal, loopback, or reserved networks.
        # This list covers common private networks, loopback addresses, link-local addresses,
        # and shared address space (RFC6598), for both IPv4 and IPv6.
        forbidden_networks = [
            ipaddress.ip_network("0.0.0.0/8"),      # Unspecified / Multicast / Broadcast
            ipaddress.ip_network("10.0.0.0/8"),     # Private-use network (RFC1918)
            ipaddress.ip_network("127.0.0.0/8"),    # Loopback network (RFC1122)
            ipaddress.ip_network("169.254.0.0/16"), # Link-local network (RFC3927)
            ipaddress.ip_network("172.16.0.0/12"),  # Private-use network (RFC1918)
            ipaddress.ip_network("192.168.0.0/16"), # Private-use network (RFC1918)
            ipaddress.ip_network("100.64.0.0/10"),  # Shared Address Space (RFC6598)
            ipaddress.ip_network("::1/128"),        # IPv6 Loopback address
            ipaddress.ip_network("fc00::/7"),       # IPv6 Unique Local Address (ULA)
            ipaddress.ip_network("fe80::/10")       # IPv6 Link-local Address
        ]

        # Iterate through all resolved IP addresses and check if any fall into forbidden ranges.
        for ip_str in resolved_ips:
            try:
                ip_addr_obj = ipaddress.ip_address(ip_str)
                for network in forbidden_networks:
                    if ip_addr_obj in network:
                        abort(400, "Access to internal, loopback, or reserved IP addresses is forbidden.")
            except ipaddress.AddressValueError:
                # Should not happen with valid IP strings from getaddrinfo, but as a safeguard.
                abort(500, "Internal error: Malformed IP address detected during validation.")
            except Exception:
                # Catch any other unexpected errors during IP validation.
                abort(500, "Error during IP address validation.")

        # If all checks pass, the URL is considered safe for external requests.
        with urlopen(target_url, timeout=5) as response:
            return response.read(200).decode("utf-8", errors="ignore")

    except ValueError as e:
        # urlparse might raise ValueError for severely malformed URLs.
        abort(400, f"Invalid URL format: {str(e)}")
    except Exception as e:
        # Catch any other unexpected errors during the overall process.
        abort(500, f"An unexpected error occurred: {str(e)}")
