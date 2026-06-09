def resolve_verify_mfa(
    _root,
    _info,
    challenge_id: str,
    code: str,
) -> dict:
    challenge = load_challenge(
        challenge_id
    )

    return {
        "verified": (
            challenge is not None
            and challenge["code"]
            == code
        ),
    }
