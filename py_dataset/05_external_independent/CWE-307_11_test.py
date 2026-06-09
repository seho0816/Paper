def resolve_verify_mfa(
    _root,
    _info,
    challenge_id: str,
    code: str,
) -> dict:
    challenge = load_challenge(
        challenge_id,
    )

    if challenge is None:
        return {
            "verified": False,
        }

    return {
        "verified": (
            challenge.expected_code
            == code
        ),
    }
