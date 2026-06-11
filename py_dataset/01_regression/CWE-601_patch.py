from flask import redirect, request
from urllib.parse import urlparse, urljoin


def login_success():
    redirect_url = request.args.get(
        "redirect_url",
        "/",
    )

    # CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
    # Validate the redirect_url to ensure it points to a trusted location.
    # This check ensures that the redirect URL is either a relative path
    # within the application or an absolute URL pointing to the same host.

    # Parse the base URL of the current request.
    host_url = urlparse(request.host_url)
    
    # Use urljoin to resolve the redirect_url against the host URL.
    # If redirect_url is an absolute URL (e.g., "http://malicious.com"),
    # urljoin will return it unchanged.
    # If redirect_url is relative (e.g., "/dashboard"), urljoin will combine it
    # with host_url to form "http://your_app.com/dashboard".
    target_url = urlparse(urljoin(request.host_url, redirect_url))

    # Check if the target URL's scheme is 'http' or 'https' and
    # if its network location (domain:port) matches that of the current host.
    # This prevents redirection to external domains or non-web schemes.
    is_safe = (target_url.scheme in ('http', 'https')) and \
              (host_url.netloc == target_url.netloc)

    if not is_safe:
        # If the redirect_url is not safe (e.g., points to an external domain
        # or uses an untrusted scheme), default to a safe internal path.
        redirect_url = '/'

    return redirect(
        redirect_url,
    )
