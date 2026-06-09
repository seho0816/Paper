import hmac

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

    stored_code_bytes = challenge["code"].encode('utf-8')
    provided_code_bytes = code.encode('utf-8')

    if not hmac.compare_digest(stored_code_bytes, provided_code_bytes):
        return None

    return challenge["account_id"]
