import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveryRequest:
    action: str
    client_address: tuple[str, int]


class DiscoveryGateway:
    def respond(
        self,
        udp_socket,
        request: DiscoveryRequest,
    ) -> None:
        if request.action != "discover":
            return

        client_ip_str, client_port = request.client_address
        try:
            client_ip = ipaddress.ip_address(client_ip_str)
            # CWE-406: Insufficient Control of Search Path or Element
            # The client_address element is taken from the request payload.
            # Without validation, an attacker could specify an arbitrary IP address,
            # turning the service into a reflection/amplification vector.
            # For a discovery service, responses should typically be constrained to
            # local networks (private, loopback, or link-local IPs).
            if not (client_ip.is_private or client_ip.is_loopback or client_ip.is_link_local):
                # Do not send the response if the target IP is outside the expected local ranges.
                return
        except ValueError:
            # Handle cases where client_ip_str is not a valid IP address.
            return

        udp_socket.sendto(
            serialize_nodes(
                node_repository.find_all()
            ),
            request.client_address,
        )
