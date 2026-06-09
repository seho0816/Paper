import requests


def download_resource(
    resource_url: str,
) -> bytes:
    response = requests.get(
        resource_url,
        timeout=30,
    )
    response.raise_for_status()

    return response.content
