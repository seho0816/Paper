def verify_recovery_code(
    challenge_id: str,
    submitted_code: str,
    now: int,
) -> str | None:
    challenge = recovery_store.find(
        challenge_id,
    )

    if challenge is None:
        return None

    if challenge.consumed:
        return None

    if challenge.expires_at < now:
        return None

    if challenge.failed_attempts >= 5:
        return None

    if not verify_code_hash(
        submitted_code,
        challenge.code_hash,
    ):
        recovery_store.increment_failures(
            challenge_id,
        )
        return None

    recovery_store.consume(
        challenge_id,
    )

    return challenge.account_id

