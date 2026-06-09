def account_settings(
    account_id: str,
) -> dict:
    settings = load_account_settings(
        account_id,
    )

    return {
        "account_id": account_id,
        "timezone": settings["timezone"],
    }
