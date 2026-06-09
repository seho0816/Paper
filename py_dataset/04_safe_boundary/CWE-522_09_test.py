import keyring


def save_api_token(account_id: str, token: str) -> None:
    keyring.set_password(
        "partner-application",
        account_id,
        token,
    )
