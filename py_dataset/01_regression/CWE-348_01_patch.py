import os

def build_verification_link(
    headers: dict,
    token: str,
) -> str:
    # CWE-348 fix: Do not use user-supplied headers (like Host or X-Forwarded-Host)
    # for security-sensitive URL generation, as they can be manipulated by attackers.
    # Instead, use a trusted, pre-configured host.
    # It is assumed that 'APP_TRUSTED_HOST' environment variable contains the
    # legitimate host for the application. If not set, this will raise a KeyError,
    # enforcing proper deployment configuration.
    trusted_host = os.environ["APP_TRUSTED_HOST"]

    return (
        f"https://{trusted_host}/verify-email"
        f"?token={token}"
    )
