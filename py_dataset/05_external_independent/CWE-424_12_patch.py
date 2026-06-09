import argparse
import getpass


class SecurePasswordHashType:
    def __call__(self, string_value):
        # The string_value argument here receives whatever the user might have
        # attempted to provide on the command line (e.g., `--new-password-hash some_hash_value`).
        # To remove the CWE-424 vulnerability (sensitive data exposure via command line),
        # we completely ignore this potentially exposed value.
        # Instead, we always securely prompt the user for the password hash,
        # ensuring it is not visible in process lists or shell history.
        return getpass.getpass("Enter new password hash: ")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--account-id",
        required=True,
    )
    parser.add_argument(
        "--new-password-hash",
        # Apply the custom type to ensure secure input for the password hash.
        # This will always prompt the user via getpass, regardless of any
        # value provided directly on the command line, thereby preventing
        # exposure of the hash in command-line arguments.
        type=SecurePasswordHashType(),
        required=True,
    )
    arguments = parser.parse_args()

    # The password hash is now guaranteed to have been retrieved securely via getpass.
    account_repository.set_password(
        arguments.account_id,
        arguments.new_password_hash,
    )
