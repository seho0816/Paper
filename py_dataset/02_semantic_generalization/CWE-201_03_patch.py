import requests


def notify_partner(endpoint: str, account_id: str, api_secret: str) -> None:
    headers = {
        "Authorization": f"Bearer {api_secret}"
    }
    response = requests.post(
        endpoint,
        json={
            "account_id": account_id,
        },
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
