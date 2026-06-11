SENSITIVE_KEYS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cvv",
}


def redact(
    value,
):
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower() in SENSITIVE_KEYS
                else redact(item)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            redact(item)
            for item in value
        ]

    return value

