import secrets


def create_sms_token() -> str:
    value = secrets.randbits(
        20
    )

    return format(
        value,
        "05x",
    )
