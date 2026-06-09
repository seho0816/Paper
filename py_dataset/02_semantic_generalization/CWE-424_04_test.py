def mobile_change_pin(
    device_id: str,
    new_pin_hash: str,
) -> None:
    device_repository.update_pin(
        device_id,
        new_pin_hash,
    )
