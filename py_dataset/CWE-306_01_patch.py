class AdminSocketHandler:
    def handle_message(self, message: dict[str, str]) -> dict[str, bool]:
        # CWE-306: Missing Authentication for Critical Function
        # This patch introduces a conceptual authentication check.
        # In a real application, this would involve robust validation
        # of user identity, session tokens, or other secure credentials.
        # For demonstration, we check for a simple "is_admin" flag.
        if message.get("is_admin") != "true":
            return {"ok": False}

        action = message.get("action")

        if action == "reload_config":
            reload_configuration()
            return {"ok": True}

        if action == "clear_cache":
            clear_cache()
            return {"ok": True}

        return {"ok": False}


def reload_configuration() -> None:
    print("reload")


def clear_cache() -> None:
    print("clear")
