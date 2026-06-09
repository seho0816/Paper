import argparse
import secrets


def provision_admin() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--username",
        default="admin",
    )
    parser.add_argument(
        "--password",
        default=secrets.token_urlsafe(16),
    )
    arguments = parser.parse_args()

    create_administrator(
        arguments.username,
        arguments.password,
    )
