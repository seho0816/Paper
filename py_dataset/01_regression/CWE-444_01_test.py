def parse_headers(
    header_lines: list[bytes],
) -> dict[bytes, bytes]:
    headers = {}

    for line in header_lines:
        name, value = line.split(
            b":",
            1,
        )
        headers[
            name.strip().lower()
        ] = value.strip()

    return headers


def request_body_length(
    header_lines: list[bytes],
) -> int:
    headers = parse_headers(
        header_lines
    )

    return int(
        headers.get(
            b"content-length",
            b"0",
        )
    )
