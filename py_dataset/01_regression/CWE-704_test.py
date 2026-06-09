def parse_account_flags(
    payload: dict,
) -> dict:
    return {
        "email_verified": bool(
            payload.get(
                "email_verified"
            )
        ),
        "mfa_enabled": bool(
            payload.get(
                "mfa_enabled"
            )
        ),
    }
