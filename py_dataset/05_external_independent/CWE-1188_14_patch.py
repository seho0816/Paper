def load_operator_console(options: dict | None = None):
    settings = {
        "require_operator_login": True,  # CWE-1188: Default to requiring login for security
        "audit_commands": False,
    }
    settings.update(options or {})
    return OperatorConsole(settings)
