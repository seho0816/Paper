import urllib.parse

def verify_origin(
    headers: dict,
    requested_origin: str,
) -> bool:
    request_origin_header = headers.get("Origin")

    if not request_origin_header:
        # If the Origin header is missing, it's generally considered an invalid origin
        # for sensitive operations, as modern browsers typically include it for cross-origin requests.
        return False

    def get_normalized_port(parsed_url) -> int | None:
        """
        Returns the port number, normalizing default HTTP/HTTPS ports.
        """
        if parsed_url.port is not None:
            return parsed_url.port
        if parsed_url.scheme == 'http':
            return 80
        if parsed_url.scheme == 'https':
            return 443
        return None

    try:
        # Parse both the requested origin and the origin from the header
        parsed_request_origin = urllib.parse.urlparse(request_origin_header)
        parsed_requested_origin = urllib.parse.urlparse(requested_origin)
    except ValueError:
        # Handle cases where origin strings might be malformed and cannot be parsed
        return False

    # Compare the scheme, hostname (case-insensitive), and normalized port.
    # This provides a robust comparison that accounts for variations like
    # 'https://example.com' vs 'https://example.com:443' being the same origin,
    # and correctly distinguishes 'http://example.com' from 'https://example.com'.
    # Hostnames are case-insensitive according to RFCs, so converting to lower case ensures correctness.
    return (
        parsed_request_origin.scheme == parsed_requested_origin.scheme and
        (parsed_request_origin.hostname or '').lower() == (parsed_requested_origin.hostname or '').lower() and
        get_normalized_port(parsed_request_origin) == get_normalized_port(parsed_requested_origin)
    )
