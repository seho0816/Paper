def resolve_verify_access_token(
    _root,
    _info,
    token: str,
) -> dict:
    expected = load_access_token()

    return {
        "valid": (
            token
            == expected
        ),
    }
