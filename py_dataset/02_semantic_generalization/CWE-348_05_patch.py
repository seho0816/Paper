import re
from urllib.parse import urlsplit

def canonical_url(
    headers: dict,
    path: str,
) -> str:
    host = headers.get(
        "Host",
        "",
    )

    # CWE-348: Use of a Mechanism that is not designed for Filtering Sensitive Information.
    # The 'Host' header is user-controlled and directly concatenated into the URL,
    # which can lead to various attacks if not properly validated.
    # This includes HTTP Host header injection, HTTP response splitting (CRLF injection),
    # URL spoofing, or open redirect if the application later redirects.

    # 1. Prevent HTTP Response Splitting by disallowing newline characters.
    if "\n" in host or "\r" in host:
        return "" # Reject host headers containing newline characters.

    # 2. Parse the host header to ensure it contains only the host and optional port,
    #    and not unexpected path, query, or fragment components.
    #    Prepend "//" to treat the string as a network location.
    parsed_url = urlsplit(f"//{host}")

    # Extract the network location (host and port) as provided by urlsplit.
    # If the Host header contained something like "example.com/foo?bar",
    # urlsplit would put "/foo" into .path and "?bar" into .query.
    # We only want the netloc part, and only if path/query/fragment are empty.
    validated_netloc = parsed_url.netloc

    # 3. Reject if the host header contained any path, query, or fragment components.
    if parsed_url.path or parsed_url.query or parsed_url.fragment:
        return ""

    # 4. Validate the characters within the extracted netloc.
    #    A `Host` header should consist of alphanumeric characters, hyphens, dots,
    #    colons (for port), and square brackets (for IPv6 literals).
    #    This regex ensures no other characters (e.g., spaces, quotes, slashes, percent-encoding)
    #    are present, preventing injection of malicious characters that `urlsplit`
    #    might not reject as part of `netloc`.
    #    This pattern is designed to be efficient and prevent ReDoS vulnerabilities.
    VALID_HOST_CHARS_PATTERN = re.compile(r"^[a-zA-Z0-9.\-:\[\]]+$")

    # Reject if the netloc is empty or contains invalid characters.
    if not validated_netloc or not VALID_HOST_CHARS_PATTERN.match(validated_netloc):
        return ""

    # If all checks pass, the host string is considered safe for concatenation.
    return (
        "https://"
        + validated_netloc
        + path
    )
