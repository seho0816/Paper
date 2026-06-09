import secrets


def create_email_code() -> str:
    return (
        f"{secrets.randbelow(10_000):04d}"
    )
