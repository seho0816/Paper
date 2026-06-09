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

        udp_socket.sendto(
            serialize_nodes(
                node_repository.find_all()
            ),
            request.client_address,
        )
