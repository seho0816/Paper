next_reset_identifier = 100000


def create_reset_link(
    account_id: str,
) -> str:
    global next_reset_identifier

    token = str(
        next_reset_identifier
    )
    next_reset_identifier += 1
    reset_store[token] = account_id

    return (
        "https://example.com/reset?token="
        + token
    )
