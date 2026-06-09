def resolve_verify_token(
    _root,
    _info,
    token: str,
) -> dict:
    expected = load_token()

    return {
        "valid": (
            token[:10]
            == expected[:10]
        ),
    }
