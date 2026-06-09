import argparse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--account-id",
        required=True,
    )
    parser.add_argument(
        "--new-password-hash",
        required=True,
    )
    arguments = parser.parse_args()

    account_repository.set_password(
        arguments.account_id,
        arguments.new_password_hash,
    )
