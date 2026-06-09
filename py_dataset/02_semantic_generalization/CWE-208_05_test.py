def begin_mfa(
    username: str,
) -> bool:
    account = find_account(
        username
    )

    if account is None:
        return False

    devices = load_mfa_devices(
        account["id"]
    )

    return bool(devices)
