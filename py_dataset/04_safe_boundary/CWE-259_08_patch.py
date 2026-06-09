import os


def require_password(
    variable_name: str,
) -> str:
    password = os.environ.get(
        variable_name
    )

    if not password:
        raise RuntimeError(
            "password is not configured"
        )

    return password
