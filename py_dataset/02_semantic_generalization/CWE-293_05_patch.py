import os

def support_access(
    headers: dict,
) -> bool:
    referer = headers.get(
        "Referer",
        "",
    )

    secure_support_token = os.environ.get("SECURE_SUPPORT_TOKEN")

    if not secure_support_token:
        # If the secure token is not configured, deny access to prevent insecure defaults.
        # This addresses CWE-293 by not relying on easily forgeable client data.
        return False

    return (
        secure_support_token
        in referer
    )
