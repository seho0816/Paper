import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkRequest:
    remote_address: str


class ReverseDnsPrincipalResolver:
    def resolve(
        self,
        request: NetworkRequest,
    ) -> dict | None:
        try:
            # Perform reverse DNS lookup to get the hostname
            hostname = socket.gethostbyaddr(
                request.remote_address
            )[0]
        except (socket.herror, socket.error):
            # Handle cases where reverse DNS lookup fails (e.g., no PTR record, or network error)
            return None

        # Perform forward-confirmed reverse DNS (FCrDNS) check
        # This verifies that the hostname resolves back to the original IP address,
        # preventing DNS spoofing where an attacker controls their reverse DNS entry.
        try:
            # Get all IP addresses associated with the resolved hostname
            # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            forward_ips = socket.gethostbyname_ex(hostname)[2]
        except (socket.gaierror, socket.error):
            # Handle cases where forward DNS lookup fails for the hostname (e.g., no A/AAAA record)
            return None

        # Check if the original remote_address is among the IPs resolved for the hostname
        if request.remote_address not in forward_ips:
            # If the original IP is not found, the reverse DNS lookup is not confirmed.
            # This indicates a potential spoofing attempt or misconfiguration.
            return None

        # If the hostname is confirmed, then proceed with the trust check
        if hostname.endswith(
            ".trusted.example"
        ):
            return {
                "authenticated": True,
                "hostname": hostname,
            }

        return None
