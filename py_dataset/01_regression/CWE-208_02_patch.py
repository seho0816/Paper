import hmac

def verify_api_token(
    submitted: str,
    expected: str,
) -> bool:
    # CWE-208: Information Exposure Through Timing Discrepancy
    # The original implementation had a timing side-channel vulnerability
    # where an attacker could deduce information about the 'expected' token
    # by observing the time it took for the function to return.
    # hmac.compare_digest() performs a constant-time comparison,
    # which mitigates this timing attack.
    # It also handles differing string lengths securely.
    return hmac.compare_digest(submitted.encode('utf-8'), expected.encode('utf-8'))
