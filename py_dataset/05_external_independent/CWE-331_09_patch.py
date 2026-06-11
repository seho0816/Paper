import secrets


def create_sms_token() -> str:
    value = secrets.randbits(
        32  # Increased entropy from 20 bits to 32 bits to mitigate CWE-331
    )

    return format(
        value,
        "08x",  # Adjusted format string to match 32 bits (8 hexadecimal characters)
    )
