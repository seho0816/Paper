def resolve_maintenance_login(
    _root,
    _info,
    password: str,
) -> dict:
    authenticated = (
        password
        == "maintenance-console"
    )

    return {
        "authenticated": authenticated,
    }
