import argparse


def provision_admin() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--username",
        default="admin",
    )
    parser.add_argument(
        "--password",
        default="admin123",
    )
    arguments = parser.parse_args()

    create_administrator(
        arguments.username,
        arguments.password,
    )
