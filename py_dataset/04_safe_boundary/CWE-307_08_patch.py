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

    # CWE-307: Improper Restriction of Excessive Authentication Attempts
    # The initial check for failed_attempts is good, but a race condition could allow
    # multiple concurrent incorrect attempts to increment the counter past the limit
    # before the lockout is fully effective.
    # We must ensure that after incrementing, the most up-to-date count is checked.
    if challenge.failed_attempts >= 5:
        return False

    if challenge.code == submitted_code:
        consume_challenge(challenge_id)
        return True
    else:
        # Increment failed attempts for an incorrect code.
        increment_failed_attempts(
            challenge_id,
        )
        # To mitigate CWE-307 race conditions, immediately re-load the challenge
        # to get the latest failed_attempts count. This ensures that even if
        # multiple concurrent requests incremented the counter, the lockout
        # decision is based on the most current state.
        updated_challenge = load_challenge(
            challenge_id,
        )
        if updated_challenge is None or updated_challenge.failed_attempts >= 5:
            return False # Lock out if it's now over the limit

        return False # Code was incorrect but not yet locked out
