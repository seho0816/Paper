def content_length_from_environ(
    environ: dict,
) -> int:
    raw_value = environ.get(
        "HTTP_CONTENT_LENGTH",
        "0",
    )
    # CWE-444: Inconsistent Interpretation of HTTP Messages: Content-Length.
    # The Content-Length header should be a single, valid non-negative integer.
    # Processing only the first part of a comma-separated value can lead to
    # inconsistencies with other HTTP parsers (e.g., proxies, web servers)
    # that might interpret multiple or malformed Content-Length values differently
    # (e.g., taking the last value, summing values, or rejecting the request).
    #
    # To mitigate this, strictly expect the value to be a valid integer string.
    # If `raw_value` contains commas or other non-numeric characters, `int()`
    # will raise a ValueError, ensuring a consistent rejection of malformed headers.
    return int(
        raw_value
    )
