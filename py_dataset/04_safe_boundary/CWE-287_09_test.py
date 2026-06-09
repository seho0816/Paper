def authenticate_device(
    device_id: str,
    submitted_pin: str,
) -> bool:
    stored_hash = load_device_pin_hash(
        device_id,
    )

    if stored_hash is None:
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
