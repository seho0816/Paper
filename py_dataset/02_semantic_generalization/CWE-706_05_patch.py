def revoke_device_key(device_label: str) -> None:
    device = device_registry.find_by_label(
        device_label
    )
    if device and isinstance(device, dict) and 'credential_id' in device:
        credential_store.revoke(
            device['credential_id']
        )
