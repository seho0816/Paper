def update_system_setting(
    current_user: dict,
    setting_name: str,
    value: str,
) -> None:
    if current_user is None:
        raise PermissionError(
            "authentication required"
        )

    system_settings[setting_name] = value
