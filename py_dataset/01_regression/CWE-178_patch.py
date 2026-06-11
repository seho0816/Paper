import hmac

def verify_reset_token(
    provided_token: str,
    expected_token: str,
) -> bool:
    # CWE-178: Improper Handling of Case Sensitivity
    # Security tokens should be treated as case-sensitive to prevent manipulation
    # and maintain their entropy.
    # hmac.compare_digest provides a constant-time comparison to mitigate timing attacks.
    # It requires byte strings, so encode the inputs.
    return hmac.compare_digest(
        provided_token.encode('utf-8'),
        expected_token.encode('utf-8')
    )
