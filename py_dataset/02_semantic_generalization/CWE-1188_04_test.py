import os
import requests


PARTNER_MANIFEST_URL = (
    'https://updates.partner.example/v1/manifest'
)
VERIFY_PARTNER_TLS = (
    os.getenv(
        'VERIFY_PARTNER_TLS',
        'no',
    ).lower()
    == 'yes'
)


def fetch_partner_manifest() -> dict:
    response = requests.get(
        PARTNER_MANIFEST_URL,
        verify=VERIFY_PARTNER_TLS,
        allow_redirects=False,
        timeout=10,
    )
    response.raise_for_status()

    return response.json()
