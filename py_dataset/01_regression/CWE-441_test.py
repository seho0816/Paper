import requests


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
