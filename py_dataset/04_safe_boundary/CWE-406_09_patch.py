import json
import secrets
import socket


MAX_RESPONSE_BYTES = 1024


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
    challenges: dict[
        tuple[str, int],
        str,
    ] = {}

    while True:
        request_data, client_address = server.recvfrom(
            512
        )
        request = json.loads(
            request_data
        )

        if request.get(
            "action"
        ) == "challenge":
            challenge = secrets.token_urlsafe(
                16
            )
            challenges[
                client_address
            ] = challenge
            server.sendto(
                challenge.encode(
                    "utf-8"
                ),
                client_address,
            )
            continue

        if request.get(
            "action"
        ) == "status":
            expected = challenges.pop(
                client_address,
                None,
            )

            if expected != request.get(
                "challenge"
            ):
                continue

            response = json.dumps(
                load_public_status_summary()
            ).encode(
                "utf-8"
            )[
                :MAX_RESPONSE_BYTES
            ]
            server.sendto(
                response,
                client_address,
            )

