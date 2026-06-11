def unlock_device(
    device_id: str,
    submitted_pin: str,
) -> dict | None:
    device = load_device(device_id)

    if device is None:
        return None

    # CWE-287 fix: Add proper authentication logic by verifying the submitted PIN
    # It is assumed that the 'device' object contains the correct 'pin' attribute
    # for comparison. For sensitive production systems, password hashing (e.g., bcrypt)
    # should be used, meaning device.pin would store a hash and submitted_pin would
    # be hashed before comparison. For a simple PIN as implied here, direct
    # string comparison is used.
    if submitted_pin != device.pin:
        # PIN does not match, authentication failed
        return {
            "device_id": device_id,
            "authenticated": False,
        }

    # If PIN matches, proceed to mark the device as authenticated
    mark_device_authenticated(
        device_id,
    )

    return {
        "device_id": device_id,
        "authenticated": True,
    }
