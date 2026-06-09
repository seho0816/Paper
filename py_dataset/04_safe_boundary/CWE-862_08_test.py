def update_system_setting(
    current_user: dict,
    setting_name: str,
    value: str,
) -> None:
    if current_user.get("role") != "admin":
        raise PermissionError(
            "administrator required"
        )

    system_settings[setting_name] = value
