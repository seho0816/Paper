import os

def resolve_maintenance_login(
    _root,
    _info,
    password: str,
) -> dict:
    expected_password = os.environ.get("MAINTENANCE_PASSWORD")

    authenticated = (
        password
        == expected_password
    )

    return {
        "authenticated": authenticated,
    }
