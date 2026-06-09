def unlock_device(
    device_id: str,
    submitted_pin: str,
) -> dict | None:
    device = load_device(device_id)

    if device is None:
        return None

    mark_device_authenticated(
        device_id,
    )

    return {
        "device_id": device_id,
        "authenticated": True,
    }
