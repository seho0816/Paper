import os

import requests


def require_secret(name: str) -> str:
    value = os.environ.get(name)

    if not value:
        raise RuntimeError(
            f"required secret is not configured: {name}"
        )

    return value


def fetch_partner_orders() -> dict:
    api_token = require_secret("PARTNER_API_TOKEN")

    response = requests.get(
        "https://partner.example.com/orders",
        headers={
            "Authorization": f"Bearer {api_token}",
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()

