from urllib.parse import urlparse, urlunparse

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

    # Reconstruct the URL from its parsed and validated components.
    # This is a critical step to mitigate Server-Side Request Forgery (CWE-918).
    # It ensures that the URL used for the actual request is exactly what was validated
    # by urlparse, preventing potential discrepancies between urlparse's interpretation
    # and requests.get's interpretation of the original 'image_url' string.
    # Such discrepancies could lead to hostname bypasses or other unintended targets.
    # Since username/password are explicitly disallowed, 'parsed.netloc' will safely
    # represent the 'host[:port]' part that passed the ALLOWED_HOSTS check.
    safe_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    response = requests.get(
        safe_url,
        timeout=5,
        allow_redirects=False,
    )
    response.raise_for_status()

    return response.content
