COMMON_PASSWORDS = {
    "password",
    "password123",
    "qwerty123",
    "welcome1",
}


def validate_password(
    username: str,
    password: str,
) -> None:
    normalized = password.strip()

    if len(
        normalized
    ) < 12:
        raise ValueError(
            "password too short"
        )

    if normalized.casefold() in COMMON_PASSWORDS:
        raise ValueError(
            "common password"
        )

    if username.casefold() in normalized.casefold():
        raise ValueError(
            "password contains username"
        )

    if len(
        set(normalized)
    ) < 6:
        raise ValueError(
            "password lacks diversity"
        )
