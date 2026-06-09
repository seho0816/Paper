reset_tokens = {
    "ABCD-1234": {
        "account_id": "account-1",
        "valid": True,
    },
}


def reset_password(
    token: str,
    new_password: str,
) -> bool:
    record = reset_tokens.get(token)

    if record is None:
        return False

    update_password(
        record["account_id"],
        new_password,
    )

    return True
