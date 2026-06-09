import os
from flask import request, current_app


def invitation_link(
    invitation_token: str,
) -> str:
    # CWE-348: Use of Hard-coded Cryptographic Key.
    # The vulnerability here is the implicit reliance on 'request.host_url',
    # which derives the base URL from the 'Host' header of the incoming HTTP request.
    # This header can be manipulated by an attacker (Host Header Injection),
    # leading to the generation of links pointing to malicious domains.
    # The 'scheme' (HTTP/HTTPS) is also derived from the request and can be downgraded.
    #
    # The fix involves using a trusted, 'hard-coded' (i.e., securely configured) base URL
    # for the application, rather than relying on an untrusted value from the request.

    # Prioritize a full trusted base URL from an environment variable.
    # This provides a 'hard-coded' trusted source for the complete URL, including scheme.
    trusted_base_url = os.environ.get("FLASK_TRUSTED_BASE_URL")

    if trusted_base_url:
        # Ensure the base URL explicitly uses HTTPS for security.
        if not trusted_base_url.startswith("https://"):
            if trusted_base_url.startswith("http://"):
                trusted_base_url = "https://" + trusted_base_url[len("http://"):]
            else:
                trusted_base_url = "https://" + trusted_base_url
        # Ensure the base URL ends with a slash for consistent path concatenation.
        if not trusted_base_url.endswith('/'):
            trusted_base_url += '/'
    else:
        # If no environment variable is set, fall back to Flask's SERVER_NAME configuration.
        # This acts as the primary 'hard-coded' trusted key for the hostname.
        # SERVER_NAME typically only provides the hostname (e.g., "example.com").
        server_name = current_app.config.get("SERVER_NAME")
        if server_name:
            # Construct the base URL using HTTPS and the trusted SERVER_NAME.
            # We force HTTPS as a security best practice for invitation links.
            trusted_base_url = f"https://{server_name}/"

    # If after checking both environment variable and SERVER_NAME,
    # no trusted base URL can be determined, it means the application is not
    # securely configured to generate external links.
    # The most secure action is to prevent the generation of a potentially insecure link.
    # Raising an error is appropriate to signal this critical configuration absence,
    # as returning an empty or dummy string is forbidden by rules, and returning an
    # insecure value is the vulnerability itself.
    if not trusted_base_url:
        raise RuntimeError(
            "Application is not securely configured to generate external links. "
            "Please set 'SERVER_NAME' in app.config or 'FLASK_TRUSTED_BASE_URL' "
            "environment variable with a trusted base URL."
        )

    return (
        trusted_base_url
        + "accept-invitation?token="
        + invitation_token
    )
