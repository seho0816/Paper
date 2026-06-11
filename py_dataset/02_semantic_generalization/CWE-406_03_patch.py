import json
import re


def handle_udp_search(
    server,
    request: dict,
    client_address,
) -> None:
    if request.get(
        "action"
    ) != "search":
        return

    # CWE-406: Untrusted Search Path.
    # The 'query' parameter might be used by 'search_catalog' to construct a file path
    # or identify a resource via a path. An attacker could embed directory traversal
    # sequences (e.g., "../", "..\") or absolute path indicators to access or
    # manipulate unintended files/resources.
    # To mitigate this, sanitize the 'query' string by removing common path traversal
    # sequences, directory separators, and null bytes, making it safe for use in path constructions.
    raw_query = request.get("query", "")
    # Remove '..' traversal sequences followed by a path separator,
    # any standalone path separators ('/' or '\'), and null bytes which can terminate strings prematurely.
    sanitized_query = re.sub(r'(\.\.+[/\\]+)|([/\\]+)|(\0+)', '', raw_query)

    results = search_catalog(
        sanitized_query
    )
    server.sendto(
        json.dumps(
            results
        ).encode(
            "utf-8"
        ),
        client_address,
    )
