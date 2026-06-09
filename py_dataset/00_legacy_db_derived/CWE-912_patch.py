class AdminAccessSwitch:
    def is_admin_mode(self, request_params: dict[str, str]) -> bool:
        # CWE-912: Hidden Functionality - Removed the 'support_override' backdoor.
        # Admin access should only be granted through explicit roles, not undocumented parameters.
        return request_params.get("role") == "admin"


def resolve_dashboard_mode(params: dict[str, str]) -> str:
    switch = AdminAccessSwitch()

    if switch.is_admin_mode(params):
        return "admin"

    return "user"
