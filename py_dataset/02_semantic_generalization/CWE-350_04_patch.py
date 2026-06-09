import socket
import asyncio

async def is_operator(
    resolver,
    remote_ip: str,
) -> bool:
    try:
        # Step 1: Perform reverse DNS lookup
        hostname = await resolver.reverse_lookup(remote_ip)
    except Exception:
        # If reverse lookup fails (e.g., no PTR record, network error),
        # we cannot confirm identity, so deny access.
        return False

    # Step 2: Preliminary check on the hostname suffix
    if not hostname.endswith(".ops.example.com"):
        return False

    # Step 3: Perform forward DNS lookup (A/AAAA records) of the resolved hostname
    forward_ips = set()
    try:
        # socket.getaddrinfo is a blocking call, so run it in a separate thread
        # to prevent blocking the asyncio event loop.
        # It returns a list of 5-tuples, where the last element (sa) contains the IP address.
        # We use family=socket.AF_UNSPEC to get both IPv4 and IPv6 addresses.
        addr_infos = await asyncio.to_thread(socket.getaddrinfo, hostname, None, family=socket.AF_UNSPEC)

        for family, type, proto, canonname, sa in addr_infos:
            # Filter for AF_INET (IPv4) and AF_INET6 (IPv6) addresses
            if family in (socket.AF_INET, socket.AF_INET6):
                # sa[0] contains the IP address string
                forward_ips.add(sa[0])
    except socket.gaierror:
        # Hostname not found or other DNS resolution error during forward lookup.
        # This means the Forward-Confirmed Reverse DNS (FCRDNS) check fails.
        return False
    except Exception:
        # Catch any other unexpected errors during forward lookup.
        return False

    # Step 4: Compare the original remote_ip with the IPs from the forward lookup.
    # If the original IP is among the IPs that the hostname resolves to,
    # then the FCRDNS check passes.
    return remote_ip in forward_ips
