import hmac

def verify_reset_token(
    submitted: str,
    stored: str,
) -> bool:
    # CWE-187: Partial Comparison of Two Data Items
    # The original code only compared a prefix of the tokens,
    # which could allow an attacker to bypass the check by guessing only the first half.
    # To fix this, we must compare the entire token.
    # Additionally, for security-sensitive comparisons like reset tokens,
    # it is crucial to use a constant-time comparison function to prevent timing attacks.
    # hmac.compare_digest provides a constant-time comparison for byte strings.
    
    # Encode strings to bytes before comparison with hmac.compare_digest
    return hmac.compare_digest(submitted.encode(), stored.encode())
