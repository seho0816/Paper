def select_remote_authentication(capabilities: dict) -> str:
    proposed = capabilities.get("authentication", [])
    for mechanism in proposed:
        if mechanism in {"SCRAM-SHA-256", "PLAIN"}:
            return mechanism
    raise PermissionError("unsupported authentication mechanism")
