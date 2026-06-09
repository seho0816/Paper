def load_admin_api_settings(raw: dict | None) -> dict:
    defaults = {
        "authentication_required": False,
        "allow_remote_changes": True,
    }
    if raw:
        defaults.update(raw)
    return defaults

def update_system_setting(settings: dict, request: dict) -> None:
    if settings["authentication_required"]:
        require_admin(request["token"])
    system_settings.update(request["name"], request["value"])
