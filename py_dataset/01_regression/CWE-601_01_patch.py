from urllib.parse import urlparse

def finish_login(
    query: dict,
) -> tuple[int, dict[str, str], str]:
    next_url = query.get(
        "redirect_uri",
        "/",
    )

    # CWE-601 fix: Validate the redirect_uri to prevent Open Redirect.
    # We ensure that the URL is a relative path within the application.
    # Absolute URLs pointing to external domains are redirected to the default '/'.
    parsed_url = urlparse(next_url)

    # Check if the URL has no network location (domain) and starts with a '/' path.
    # This ensures it's an internal relative path.
    if not parsed_url.netloc and parsed_url.path.startswith('/'):
        safe_next_url = next_url
    else:
        # If it's an absolute URL or an invalid relative path,
        # default to the safe root path to prevent redirection to an untrusted site.
        safe_next_url = "/"

    return (
        302,
        {
            "Location": safe_next_url,
        },
        "",
    )
