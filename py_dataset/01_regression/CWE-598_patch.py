import requests


def fetch_profile(
    api_base_url: str,
    access_token: str,
) -> dict:
    url = f"{api_base_url}/profile"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(
        url,
        headers=headers,
        timeout=5,
    )
    response.raise_for_status()

    return response.json()
