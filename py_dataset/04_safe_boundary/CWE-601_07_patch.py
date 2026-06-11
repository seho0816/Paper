from urllib.parse import urlparse, unquote


def validate_return_path(
    candidate: str,
) -> str:
    parsed = urlparse(
        candidate,
    )

    # Reject if the URL has a scheme (e.g., http://, javascript:) or an explicit network location (e.g., example.com)
    if parsed.scheme or parsed.netloc:
        return "/"

    # Decode the candidate path to handle percent-encoded characters (e.g., %2f for /)
    # This is crucial for preventing bypasses where attackers encode characters
    # that would otherwise trigger the security checks.
    unquoted_candidate = unquote(candidate)

    # Reject if the unquoted path does not start with a single '/'
    # This ensures it's a root-relative path.
    if not unquoted_candidate.startswith("/"):
        return "/"

    # Reject if the unquoted path starts with '//'.
    # This prevents scheme-relative URLs (e.g., //attacker.com) which would otherwise
    # be interpreted by browsers as external redirects using the current page's scheme.
    if unquoted_candidate.startswith("//"):
        return "/"

    # Further enhance robustness by rejecting paths containing backslashes.
    # Backslashes are not standard in URLs and can lead to unexpected parsing
    # behavior in some browsers or platforms, potentially facilitating bypasses.
    if "\\" in unquoted_candidate:
        return "/"

    # If all checks pass, the candidate is considered a safe local path.
    return candidate
