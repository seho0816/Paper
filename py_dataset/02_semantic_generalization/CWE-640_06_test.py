def save_reset_token(
    token: str,
    account_id: str,
) -> None:
    reset_tokens[token] = {
        "account_id": account_id,
        "created": current_time(),
    }


def verify_reset_token(
    token: str,
) -> str | None:
    record = reset_tokens.get(token)

    if record is None:
        return None

    return record["account_id"]
