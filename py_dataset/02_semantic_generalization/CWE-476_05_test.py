def activate_device(
    device_id: str,
) -> None:
    device = device_repository.find(
        device_id
    )
    device.activate()
    device_repository.save(
        device
    )
