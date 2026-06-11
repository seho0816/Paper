def parse_account_flags(
    payload: dict,
) -> dict:
    def _safe_parse_bool(value):
        if isinstance(value, str):
            value_lower = value.lower()
            if value_lower == "true":
                return True
            if value_lower == "false":
                return False
            # For any other string, including "1", "0", "yes", "no", or arbitrary text,
            # return False to ensure strict parsing and prevent unexpected "truthy" values.
            return False
        # Handles None, True, False, integers (0, 1), and other non-string types.
        # bool(None) is False, bool(0) is False, bool(1) is True, bool(True) is True, etc.
        return bool(value)

    return {
        "email_verified": _safe_parse_bool(
            payload.get(
                "email_verified"
            )
        ),
        "mfa_enabled": _safe_parse_bool(
            payload.get(
                "mfa_enabled"
            )
        ),
    }
