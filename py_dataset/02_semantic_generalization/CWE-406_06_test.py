import json


def discovery_response(
    server,
    request_data: bytes,
    client_address,
) -> None:
    if request_data != b"DISCOVER":
        return

    metadata = json.dumps(
        load_all_service_metadata()
    ).encode(
        "utf-8"
    )
    server.sendto(
        metadata,
        client_address,
    )
