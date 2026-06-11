import os

def create_reset_url(
    request,
    token: str,
) -> str:
    # The original code uses `request.get_host()`, which can be manipulated via the Host header.
    # This allows an attacker to control the domain used in security-sensitive URLs,
    # leading to vulnerabilities like host header injection or open redirect.
    # To mitigate this, a trusted host name should be explicitly configured
    # (e.g., via an environment variable) and used instead.
    # This ensures that the critical security parameter (the host for the reset URL)
    # is "hard-coded" in a trusted configuration, not derived from untrusted client input.
    trusted_host = os.environ.get("TRUSTED_FRONTEND_HOST")

    if not trusted_host:
        # If the trusted host is not configured, it's a critical misconfiguration.
        # Raising an error prevents the generation of potentially malicious or broken URLs.
        raise ValueError("TRUSTED_FRONTEND_HOST environment variable not set.")

    return (
        "https://"
        + trusted_host
        + "/account/reset/"
        + token
    )
