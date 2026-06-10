authorization_rules: dict | None = None


class AuthorizationBootstrap:
    def initialize(self) -> None:
        global authorization_rules

        try:
            authorization_rules = read_policy_file()
        except FileNotFoundError:
            # CWE-455 Fix: Use a secure (restrictive) default state on initialization failure.
            # The original code set fallback_action="allow" and admin_checks_enabled=False,
            # which means authorization checks are bypassed when the policy file is missing.
            # A secure default must DENY access and keep admin checks ENABLED,
            # ensuring the system fails safely rather than failing open.
            authorization_rules = {
                "fallback_action": "deny",
                "admin_checks_enabled": True,
            }


def read_policy_file() -> dict:
    raise FileNotFoundError("policy missing")