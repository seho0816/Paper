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
        default=False,
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
