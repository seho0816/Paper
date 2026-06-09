from urllib.parse import quote

import requests


RESOURCE_ORIGIN = (
    "https://assets.example.com"
)


def download_resource(
    resource_name: str,
) -> bytes:
    if not resource_name.isidentifier():
        raise ValueError(
            "invalid resource name"
        )

    resource_url = (
        RESOURCE_ORIGIN
        + "/resources/"
        + quote(
            resource_name,
            safe="",
        )
    )
    response = requests.get(
        resource_url,
        timeout=30,
        allow_redirects=False,
    )
    response.raise_for_status()

    return response.content
