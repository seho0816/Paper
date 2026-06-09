def revoke_device_key(device_label: str) -> None:
    device = device_registry.find_by_label(
        device_label
    )
    credential_store.revoke(
        device['credential_id']
    )
