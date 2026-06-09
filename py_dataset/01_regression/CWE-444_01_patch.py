def parse_headers(
    header_lines: list[bytes],
) -> dict[bytes, bytes]:
    headers = {}
    content_length_key = b"content-length"

    for line in header_lines:
        name, value = line.split(
            b":",
            1,
        )
        
        header_name_lower = name.strip().lower()
        header_value_stripped = value.strip()

        # CWE-444: Inconsistent Interpretation of HTTP Messages
        # Specifically address Content-Length header ambiguity.
        # RFC 7230 Section 3.3.2 states that a message MUST NOT include more than
        # one Content-Length header field. If multiple are received with
        # different values, the message is malformed.
        if header_name_lower == content_length_key:
            if content_length_key in headers:
                # Multiple Content-Length headers found.
                # Check if the new value is consistent with the existing one.
                existing_value = headers[content_length_key]
                if existing_value != header_value_stripped:
                    # If values are inconsistent, raise an error to indicate a malformed request.
                    # Decoding with 'ignore' for error message to prevent new issues with non-UTF8 bytes.
                    raise ValueError(f"Inconsistent Content-Length headers: existing='{existing_value.decode(errors='ignore')}', new='{header_value_stripped.decode(errors='ignore')}'")
                # If values are consistent, the last one overwriting is acceptable.
            
            # Store the (consistent) Content-Length value.
            headers[content_length_key] = header_value_stripped
        else:
            # For all other headers, the last one encountered will overwrite previous ones.
            # This is a common and generally acceptable behavior for most HTTP headers
            # when parsing into a dictionary, unless specific headers require multi-value handling.
            headers[header_name_lower] = header_value_stripped

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
