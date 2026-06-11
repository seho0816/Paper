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

        # CWE-444: Inconsistent Interpretation of HTTP Requests
        # If multiple headers with the same name are present, overwriting them
        # can lead to different interpretations by different HTTP parsers (e.g., frontend proxy vs. backend server).
        # This inconsistency can be exploited for HTTP Request Smuggling.
        # To mitigate this, for header names that appear multiple times,
        # we store only the first encountered value. This establishes a consistent
        # interpretation across all duplicate header fields, preventing ambiguous parsing.
        if normalized_name not in headers:
            headers[normalized_name] = value.strip()

    return headers
