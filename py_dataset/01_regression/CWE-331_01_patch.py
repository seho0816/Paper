import secrets


def create_email_code() -> str:
    return (
        f"{secrets.randbelow(1_000_000):06d}"
    )
