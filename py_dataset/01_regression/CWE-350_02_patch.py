import socket


def resolve_service_identity(
    remote_ip: str,
) -> str | None:
    try:
        # Perform reverse DNS lookup.
        # This can raise socket.herror or socket.gaierror if the IP address
        # cannot be resolved to a hostname.
        hostname = socket.gethostbyaddr(remote_ip)[0]
    except (socket.herror, socket.gaierror):
        # If the reverse lookup fails, the IP is not resolvable to a hostname,
        # so it cannot be a trusted service. Return None to indicate failure.
        return None

    # Check if the resolved hostname belongs to a trusted domain.
    # This part of the logic remains as it is for initial filtering.
    if not hostname.endswith(".trusted-services.example"):
        return None

    try:
        # To prevent DNS spoofing (where an attacker controls the reverse DNS entry),
        # perform a Forward-Confirmed Reverse DNS (FCRDNS) lookup.
        # This involves resolving the obtained hostname back to IP addresses.
        # socket.gethostbyname_ex returns (canonical_hostname, aliaslist, ipaddrlist).
        # We are interested in ipaddrlist (index 2).
        forward_ips = socket.gethostbyname_ex(hostname)[2]
    except (socket.herror, socket.gaierror):
        # If the forward lookup fails for the resolved hostname,
        # the hostname is not reliably resolvable, indicating a potential spoof.
        # Return None to indicate an unconfirmed or untrusted service.
        return None

    # Finally, verify that the original remote_ip is among the IP addresses
    # returned by the forward lookup for the hostname.
    # If the original IP is not found, it means the reverse lookup was spoofed
    # or incorrect, thus the service identity cannot be trusted.
    if remote_ip not in forward_ips:
        return None

    # If all checks pass, the hostname is confirmed and belongs to a trusted service.
    return hostname
