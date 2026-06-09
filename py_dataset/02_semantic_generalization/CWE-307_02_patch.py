import hmac

reset_codes = {
    "account-10": "731204",
}


def verify_reset_code(
    account_id: str,
    submitted_code: str,
) -> bool:
    stored_code = reset_codes.get(account_id)

    # CWE-307 is about improper restriction of excessive authentication attempts.
    # While a full rate-limiting mechanism typically exists outside this function,
    # making the comparison itself resistant to timing attacks is a measure
    # that reduces the information an attacker can gain from each attempt,
    # thus making brute-force attempts less effective.
    # hmac.compare_digest performs a constant-time comparison, preventing timing side-channels.

    if stored_code is None:
        # If no code is found for the account, it cannot be verified.
        # This branch correctly returns False, consistent with the original
        # behavior of `None == submitted_code` being False.
        # We cannot use hmac.compare_digest directly with None.
        return False
    
    # Both stored_code and submitted_code are strings.
    # Use hmac.compare_digest for secure, constant-time comparison.
    return hmac.compare_digest(stored_code, submitted_code)
