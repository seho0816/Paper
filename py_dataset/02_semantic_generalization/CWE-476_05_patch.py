def activate_device(
    device_id: str,
) -> None:
    device = device_repository.find(
        device_id
    )
    if device is None:
        raise ValueError(f"Device with ID '{device_id}' not found.")
    device.activate()
    device_repository.save(
        device
    )
