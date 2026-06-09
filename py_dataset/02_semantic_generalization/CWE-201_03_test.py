import requests


def notify_partner(endpoint: str, account_id: str, api_secret: str) -> None:
    response = requests.post(
        endpoint,
        json={
            "account_id": account_id,
            "api_secret": api_secret,
        },
        timeout=10,
    )
    response.raise_for_status()
