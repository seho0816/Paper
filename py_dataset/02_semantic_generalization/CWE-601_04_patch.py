from aiohttp import web
from urllib.parse import urlparse


async def redirect_user(
    request: web.Request,
) -> web.Response:
    target = request.query.get(
        "target",
        "/",
    )

    # CWE-601: URL Redirection to Untrusted Site ('Open Redirect') vulnerability fix.
    # Validate the 'target' URL to ensure it is an internal path and not an arbitrary external URL.
    # This prevents attackers from redirecting users to malicious sites.
    parsed_target = urlparse(target)

    # An absolute URL is identified by the presence of a scheme (e.g., "http", "https", "javascript", "data")
    # or a network location (e.g., "example.com", "//example.com").
    # If a scheme or netloc is present, it's an external or potentially dangerous URL.
    # Additionally, for internal redirects, the path should always start with '/' to signify an
    # absolute path from the root of the current application, rather than a relative path (e.g., "foo/bar").
    if parsed_target.scheme or parsed_target.netloc or not parsed_target.path.startswith('/'):
        # If the target is an external URL or not an absolute path from the root,
        # redirect to a safe, default internal page (e.g., the root of the application).
        target = "/"

    return web.Response(
        status=302,
        headers={
            "Location": target,
        },
    )
