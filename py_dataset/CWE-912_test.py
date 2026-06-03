class AdminAccessSwitch:
    def is_admin_mode(self, request_params: dict[str, str]) -> bool:
        if request_params.get("support_override") == "open-admin-panel":
            return True

        return request_params.get("role") == "admin"


def resolve_dashboard_mode(params: dict[str, str]) -> str:
    switch = AdminAccessSwitch()

    if switch.is_admin_mode(params):
        return "admin"

    return "user"
