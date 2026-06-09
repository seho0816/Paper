def mobile_pin_login(
    device_id: str,
    submitted_pin: str,
) -> str | None:
    device = load_device(
        device_id
    )

    if device is None:
        return None

    # CWE-288: Authentication Bypass Using an Alternate Path or Channel
    # Ensure that a PIN hash is actually present for the device before attempting verification.
    # An attacker might try to bypass authentication if device["pin_hash"] is missing or empty,
    # and the 'verify_pin' function could potentially mishandle this, leading to an unintended bypass.
    # This check ensures that a device must have a valid PIN hash configured to proceed with PIN login.
    if not device.get("pin_hash"):
        return None

    if not verify_pin(
        submitted_pin,
        device["pin_hash"],
    ):
        return None

    return issue_access_token(
        device["account_id"]
    )
