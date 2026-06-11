def resolve_verify_mfa(
    _root,
    _info,
    challenge_id: str,
    code: str,
) -> dict:
    challenge = load_challenge(
        challenge_id
    )

    if challenge is None:
        return {"verified": False}

    current_user_id = _info.context.user.id
    challenge_owner_id = challenge["user_id"]

    if current_user_id != challenge_owner_id:
        return {"verified": False}

    return {
        "verified": (
            challenge["code"]
            == code
        ),
    }
