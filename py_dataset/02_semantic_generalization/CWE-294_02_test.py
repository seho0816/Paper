reset_tokens = {
    "reset-token": {
        "account_id": "account-1",
    },
}


def reset_password(
    token: str,
    new_password: str,
) -> bool:
    record = reset_tokens.get(
        token
    )

    if record is None:
        return False

    update_password(
        record["account_id"],
        new_password,
    )
    return True
