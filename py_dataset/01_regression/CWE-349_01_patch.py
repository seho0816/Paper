def build_profile_update(
    authenticated_context: dict,
    payload: dict,
) -> dict:
    SENSITIVE_KEYS = {
        "id", "user_id", "email_verified", "is_admin", "roles", "permissions",
        "password_hash", "account_status", "two_factor_enabled", "security_questions"
    }

    update = dict(
        authenticated_context
    )

    sanitized_payload = {
        key: value for key, value in payload.items()
        if key not in SENSITIVE_KEYS
    }

    update.update(
        sanitized_payload
    )

    return update
