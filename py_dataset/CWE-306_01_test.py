class AdminSocketHandler:
    def handle_message(self, message: dict[str, str]) -> dict[str, bool]:
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
