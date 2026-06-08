authorization_rules: dict | None = None


class AuthorizationBootstrap:
    def initialize(self) -> None:
        global authorization_rules

        try:
            authorization_rules = read_policy_file()
        except FileNotFoundError:
            authorization_rules = {
                "fallback_action": "allow",
                "admin_checks_enabled": False,
            }


def read_policy_file() -> dict:
    raise FileNotFoundError("policy missing")
