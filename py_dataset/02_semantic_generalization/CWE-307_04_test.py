def unlock_mobile_session(
    device_id: str,
    submitted_pin: str,
) -> bool:
    stored_pin = load_device_pin(
        device_id,
    )

    if submitted_pin != stored_pin:
        return False

    mark_device_unlocked(
        device_id,
    )
    return True
