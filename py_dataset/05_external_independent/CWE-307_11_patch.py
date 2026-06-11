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

    # CWE-307: Improper Restriction of Excessive Authentication Attempts
    # Implement a limit on the number of failed MFA code attempts.
    # Assume the 'challenge' object is mutable and its state (like 'attempts')
    # is implicitly persisted or handled by the surrounding framework/ORM.
    # This allows tracking attempts directly on the challenge object.
    
    # Define the maximum number of allowed attempts.
    # This value should be determined by security policy.
    MAX_MFA_ATTEMPTS = 3

    # Initialize the attempt counter if it doesn't exist on the challenge object.
    if not hasattr(challenge, 'attempts'):
        challenge.attempts = 0

    # Check if the number of attempts has exceeded the maximum allowed.
    if challenge.attempts >= MAX_MFA_ATTEMPTS:
        return {
            "verified": False,  # Block further attempts
        }

    is_verified = (challenge.expected_code == code)

    if not is_verified:
        # Increment the failed attempt counter.
        challenge.attempts += 1
        # In a real system, a mechanism would persist this change to 'challenge'.
        # For this exercise, we assume modification of the 'challenge' object
        # (e.g., an ORM managed object) is automatically persisted or handled
        # by the `load_challenge`'s context.

    return {
        "verified": is_verified,
    }
