def parse_request_headers(
    lines: list[bytes],
) -> dict[bytes, bytes]:
    headers = {}

    for line in lines:
        name, value = line.split(
            b":",
            1,
        )
        normalized_name = name.lower()

        headers[
            normalized_name
        ] = value.strip()

    return headers
