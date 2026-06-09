from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {
    "images.partner.example",
}


def download_partner_image(
    image_url: str,
) -> bytes:
    parsed = urlparse(
        image_url,
    )

    if parsed.scheme != "https":
        raise ValueError(
            "only HTTPS is allowed"
        )

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "host is not allowed"
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "URL credentials are not allowed"
        )

    response = requests.get(
        image_url,
        timeout=5,
        allow_redirects=False,
    )
    response.raise_for_status()

    return response.content
