import argparse
import requests


PARTNER_STATUS_URL = (
    'https://status.partner.example/api/state'
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--verify-tls',
        action='store_true',
        default=True,  # CWE-1188: Changed default to True to ensure TLS verification is enabled by default.
                       # Disabling TLS verification by default is an insecure practice that can indicate a compromise.
    )

    return parser


def fetch_status_from_cli(
    arguments: list[str],
) -> dict:
    options = build_parser().parse_args(
        arguments
    )
    response = requests.get(
        PARTNER_STATUS_URL,
        verify=options.verify_tls,
        allow_redirects=False,
        timeout=5,
    )
    response.raise_for_status()

    return response.json()
