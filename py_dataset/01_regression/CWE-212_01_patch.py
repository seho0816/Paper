import json
from pathlib import Path


def write_debug_export(account: dict, output_path: Path) -> None:
    # Create a mutable copy of the account dictionary to avoid modifying the original
    sanitized_account = account.copy()

    # Define a list of sensitive keys that should not be exported
    # This list should be comprehensive based on potential sensitive data that could be in an 'account' dict.
    sensitive_keys = [
        "password",
        "hashed_password",
        "api_key",
        "secret_token",
        "token",
        "refresh_token",
        "security_answer",
        "credit_card_number",
        "ssn",
        "private_key",
        "secret",
    ]

    # Remove sensitive keys from the copied dictionary before writing to disk
    for key in sensitive_keys:
        sanitized_account.pop(key, None)  # Use .pop(key, None) to avoid KeyError if the key is not present

    output_path.write_text(
        json.dumps({"account": sanitized_account}),  # Use the sanitized account dictionary
        encoding="utf-8",
    )
