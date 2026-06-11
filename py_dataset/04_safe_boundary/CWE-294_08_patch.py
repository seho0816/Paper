def verify_otp(
    challenge_id: str,
    submitted_code: str,
) -> str | None:
    challenge = otp_repository.lock_for_update(
        challenge_id
    )

    if challenge is None:
        return None

    if challenge.consumed:
        return None

    if not verify_code(
        submitted_code,
        challenge.code_hash,
    ):
        return None

    otp_repository.mark_consumed(
        challenge_id
    )

    return challenge.account_id

