def select_remote_authentication(capabilities: dict) -> str:
    proposed = capabilities.get("authentication", [])

    # Prioritize the more trusted mechanism (SCRAM-SHA-256)
    if "SCRAM-SHA-256" in proposed:
        return "SCRAM-SHA-256"

    # If SCRAM-SHA-256 is not available, then consider the less trusted mechanism (PLAIN)
    if "PLAIN" in proposed:
        return "PLAIN"

    raise PermissionError("unsupported authentication mechanism")
