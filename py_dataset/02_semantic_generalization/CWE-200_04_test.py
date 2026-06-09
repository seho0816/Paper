def account_settings(
    account_id: str,
) -> dict:
    settings = load_account_settings(
        account_id,
    )

    return {
        "account_id": account_id,
        "timezone": settings["timezone"],
        "api_secret": settings["api_secret"],
        "webhook_secret": settings["webhook_secret"],
    }
