import requests


def load_partner_data(
    endpoint: str,
    api_key: str,
) -> dict:
    headers = {
        "X-API-Key": api_key,
    }
    response = requests.get(
        endpoint,
        headers=headers,
        timeout=5,
    )
    response.raise_for_status()

    return response.json()
