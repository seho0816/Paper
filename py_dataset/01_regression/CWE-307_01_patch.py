import hmac

otp_store = {
    "member@example.com": "482911",
}


def verify_email_otp(
    email: str,
    submitted_code: str,
) -> bool:
    expected_code = otp_store.get(email)

    if expected_code is None:
        return False

    # CWE-307: Replace standard equality check with a constant-time comparison
    # to prevent timing attacks that could aid in brute-forcing authentication codes,
    # thereby restricting excessive authentication attempts more effectively.
    # hmac.compare_digest requires byte strings for comparison.
    return hmac.compare_digest(submitted_code.encode(), expected_code.encode())
