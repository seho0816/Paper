import urllib.parse

def resolve_complete_login(
    _root,
    _info,
    redirect_url: str,
) -> dict:
    parsed_url = urllib.parse.urlparse(redirect_url)

    # CWE-601: URL Redirection to Untrusted Site ('Open Redirect') vulnerability fix.
    # To prevent open redirects, ensure that the redirect_url is either a relative path
    # or an absolute URL pointing to a trusted domain.
    # Given the strict rules against dummy values or external configuration for trusted domains,
    # the safest approach without such context is to allow only relative paths.
    # If the URL contains a scheme (e.g., http, https, javascript) or a network location (domain),
    # it is considered an absolute or protocol-relative URL and is treated as unsafe.
    if parsed_url.scheme or parsed_url.netloc:
        # If the URL is absolute or protocol-relative, it could lead to an open redirect.
        # Default to a safe, internal path (e.g., the application's root) instead.
        safe_redirect_url = "/"
        return {
            "success": True,
            "redirect_url": safe_redirect_url,
        }

    # If neither scheme nor netloc is present, it's a relative path, which is considered safe.
    return {
        "success": True,
        "redirect_url": redirect_url,
    }
