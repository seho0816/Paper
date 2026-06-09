def verify_otp(
    challenge_id: str,
    submitted_code: str,
) -> bool:
    challenge = load_challenge(
        challenge_id,
    )

    if challenge is None:
        return False

    if challenge.is_expired():
        delete_challenge(challenge_id)
        return False

    if challenge.failed_attempts >= 5:
        return False

    if challenge.code != submitted_code:
        increment_failed_attempts(
            challenge_id,
        )
        return False

    consume_challenge(challenge_id)
    return True
