import hmac

def verify_access_token(
    submitted_token: str,
    expected_token: str,
) -> bool:
    # CWE-187: Partial Comparison of Two Values
    # The original code only compared the last 6 characters of the tokens,
    # which could allow an attacker to bypass authentication with a partially correct token.
    # To fix this, a full, constant-time comparison is performed using hmac.compare_digest.
    # This function compares two byte strings in a way that is resistant to timing attacks.
    return hmac.compare_digest(
        submitted_token.encode('utf-8'),
        expected_token.encode('utf-8')
    )
