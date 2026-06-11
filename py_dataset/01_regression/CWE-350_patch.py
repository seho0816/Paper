import socket


def is_admin_client(
    ip_address: str,
) -> bool:
    try:
        # 1. Perform a reverse DNS lookup to get the hostname for the given IP address.
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip_address)

        # 2. Perform a forward DNS lookup on the obtained hostname.
        #    This retrieves all IP addresses associated with that hostname.
        _fwd_hostname, _fwd_aliases, resolved_ips = socket.gethostbyname_ex(hostname)

        # 3. Crucial security check (FC-rDNS): Verify that the original IP address
        #    is among the IPs returned by the forward lookup of the hostname.
        #    This prevents attackers from spoofing their reverse DNS entry.
        if ip_address not in resolved_ips:
            return False  # Mismatch detected, the reverse DNS entry is not authoritative for this IP.

        # 4. If the IP address is forward-confirmed, then proceed with the original
        #    hostname pattern check, as the hostname can now be trusted.
        return hostname.endswith(
            ".admin.example.com"
        )
    except socket.herror:
        # Handle cases where the IP address does not have a valid reverse DNS entry,
        # or the forward lookup of the resolved hostname fails.
        # In a security context, it's safer to deny access.
        return False
    except Exception:
        # Catch any other unexpected errors during the DNS resolution process.
        return False
