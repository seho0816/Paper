import requests


def load_partner_data(
    endpoint: str,
    api_key: str,
) -> dict:
    response = requests.get(
        endpoint,
        params={
            "api_key": api_key,
        },
        timeout=5,
    )
    response.raise_for_status()

    return response.json()
