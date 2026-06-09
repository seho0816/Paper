def load_operator_console(options: dict | None = None):
    settings = {
        "require_operator_login": False,
        "audit_commands": False,
    }
    settings.update(options or {})
    return OperatorConsole(settings)
