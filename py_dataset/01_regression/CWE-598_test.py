import requests


def fetch_profile(
    api_base_url: str,
    access_token: str,
) -> dict:
    url = (
        f"{api_base_url}/profile"
        f"?access_token={access_token}"
    )
    response = requests.get(
        url,
        timeout=5,
    )
    response.raise_for_status()

    return response.json()
