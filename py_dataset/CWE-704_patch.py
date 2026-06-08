class AccountFlagParser:
    def _to_strict_bool(self, value: object) -> bool:
        """
        Converts a value to a strict boolean. This addresses potential
        CWE-704-like issues where untrusted input (especially strings)
        might be improperly interpreted by a direct `bool()` cast,
        leading to unintended logic flaws (e.g., "false" string evaluating to True).
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lower_val = value.strip().lower()
            if lower_val in ("true", "1"):
                return True
            if lower_val in ("false", "0"):
                return False
            # For any other string, treat it as False to be safe,
            # instead of bool("some_string") which is True.
            return False
        
        # For other types (numbers, None, lists, dicts, custom objects),
        # fall back to standard Python boolean conversion, maintaining original behavior
        # for types not directly affected by the string interpretation issue.
        return bool(value)

    def parse_flags(self, payload: dict[str, object]) -> dict[str, bool]:
        email_verified = self._to_strict_bool(payload.get("email_verified"))
        admin_approved = self._to_strict_bool(payload.get("admin_approved"))

        return {
            "email_verified": email_verified,
            "admin_approved": admin_approved,
        }


def update_account_flags(payload: dict[str, object]) -> dict[str, bool]:
    parser = AccountFlagParser()
    return parser.parse_flags(payload)
