import json


def handle_udp_search(
    server,
    request: dict,
    client_address,
) -> None:
    if request.get(
        "action"
    ) != "search":
        return

    results = search_catalog(
        request.get(
            "query",
            "",
        )
    )
    server.sendto(
        json.dumps(
            results
        ).encode(
            "utf-8"
        ),
        client_address,
    )
