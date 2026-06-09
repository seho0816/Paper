challenges = {
    "challenge-1": {
        "account_id": "account-1",
        "code": "392104",
    },
}


def verify_mfa(
    challenge_id: str,
    code: str,
) -> str | None:
    challenge = challenges.get(
        challenge_id
    )

    if challenge is None:
        return None

    if challenge["code"] != code:
        return None

    return challenge["account_id"]
