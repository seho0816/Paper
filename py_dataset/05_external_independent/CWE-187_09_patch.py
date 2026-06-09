import hmac

def resolve_verify_token(
    _root,
    _info,
    token: str,
) -> dict:
    expected = load_token()

    return {
        "valid": (
            hmac.compare_digest(token, expected)
        ),
    }
