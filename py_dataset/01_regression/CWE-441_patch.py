import requests
from requests.exceptions import InvalidURL


INTERNAL_ADMIN_API = (
    "http://admin-api.internal"
)
SERVICE_TOKEN = (
    "loaded-from-secret-store"
)


def forward_support_operation(
    operation: str,
    payload: dict,
) -> dict:
    # CWE-441: Unintended Proxy/Redirection to a Malicious Site
    # Validate the 'operation' argument to prevent URL injection that could
    # lead to the request being redirected or proxied to an unintended external host.
    # An 'operation' should be a path segment and not contain a scheme (e.g., "://")
    # or start with a scheme-relative indicator (e.g., "//").
    if "://" in operation or operation.startswith("//"):
        raise InvalidURL("Operation path segment cannot contain a scheme or be scheme-relative to prevent redirection attacks.")

    response = requests.post(
        f"{INTERNAL_ADMIN_API}/{operation}",
        headers={
            "Authorization": (
                f"Bearer {SERVICE_TOKEN}"
            ),
        },
        json=payload,
        timeout=5,
    )
    response.raise_for_status()

    return response.json()
