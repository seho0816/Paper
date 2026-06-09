import requests


def fetch_private_data(
    api_token: str,
) -> dict:
    response = requests.get(
        "http://partner.example.com/private",
        headers={
            "Authorization": f"Bearer {api_token}",
        },
        timeout=10,
    )
    response.raise_for_status()

    return response.json()
