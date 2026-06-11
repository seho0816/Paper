import json
import socket


def run_status_server(
    bind_address: tuple[str, int],
) -> None:
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    server.bind(
        bind_address
    )

    while True:
        request_data, client_address = server.recvfrom(
            128
        )

        if request_data == b"STATUS":
            # CWE-406: Untrusted Search Path (interpreted here as untrusted response destination)
            # To mitigate UDP amplification attacks and ensure responses are sent only to trusted sources,
            # this check ensures the server only responds to requests originating from the loopback interface.
            # This prevents the server from being used as a reflector by external, potentially spoofed, IPs.
            if client_address[0] == "127.0.0.1":
                response = json.dumps(
                    load_full_cluster_status()
                ).encode(
                    "utf-8"
                )
                server.sendto(
                    response,
                    client_address,
                )
