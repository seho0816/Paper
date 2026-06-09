def mobile_pin_login(
    device_id: str,
    submitted_pin: str,
) -> str | None:
    device = load_device(
        device_id
    )

    if device is None:
        return None

    if not verify_pin(
        submitted_pin,
        device["pin_hash"],
    ):
        return None

    return issue_access_token(
        device["account_id"]
    )
