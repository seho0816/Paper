import requests


def fetch_profile(
    api_base_url: str,
    access_token: str,
) -> dict:
    response = requests.get(
        f"{api_base_url}/profile",
        headers={
            "Authorization": (
                "Bearer "
                + access_token
            ),
        },
        timeout=5,
    )
    response.raise_for_status()

    return response.json()

