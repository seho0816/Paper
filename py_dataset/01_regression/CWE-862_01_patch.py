def update_system_setting(
    current_user: dict,
    setting_name: str,
    value: str,
) -> None:
    if current_user is None:
        raise PermissionError(
            "authentication required"
        )

    # CWE-862: Missing Authorization.
    # An authenticated user might not be authorized to update system settings.
    # Add an authorization check to ensure the user has the required permissions (e.g., admin role).
    if not current_user.get('is_admin', False):
        raise PermissionError(
            "authorization required: user is not permitted to update system settings"
        )

    system_settings[setting_name] = value
