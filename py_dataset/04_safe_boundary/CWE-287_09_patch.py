def authenticate_device(
    device_id: str,
    submitted_pin: str,
) -> bool:
    stored_hash = load_device_pin_hash(
        device_id,
    )

    # CWE-287: Improper Authentication
    # The original code only checked for `stored_hash is None`.
    # If `load_device_pin_hash` returns an empty string or other falsy value
    # instead of None for a non-existent or misconfigured device,
    # the subsequent `verify_pin_hash` call might behave unexpectedly,
    # potentially leading to an authentication bypass if it's not robust
    # against empty/invalid hash inputs.
    # This change ensures that any falsy value (None, empty string, etc.)
    # for stored_hash results in authentication failure.
    if not stored_hash:
        return False

    if not verify_pin_hash(
        submitted_pin,
        stored_hash,
    ):
        return False

    mark_device_authenticated(
        device_id,
    )
    return True
