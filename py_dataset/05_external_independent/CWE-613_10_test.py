def resolve_logout(
    _root,
    _info,
    access_token: str,
) -> dict:
    return {
        "success": True,
    }
