import hmac

def verify_recovery_code(
    submitted: str,
    expected: str,
) -> bool:
    # CWE-208 (Information Exposure Through Timing Discrepancy) is addressed by using
    # hmac.compare_digest. This function compares two strings in constant time,
    # preventing attackers from inferring information about the `expected` string
    # by observing subtle timing differences in the execution path for different `submitted` values.
    # The original character-by-character comparison with early exits for mismatches
    # or length differences allowed for timing attacks.
    # The `perform_audit_step` call was part of the vulnerable loop structure;
    # its per-character invocation is incompatible with constant-time string comparison
    # and would itself introduce timing variations if not implemented in a constant-time manner.
    # To strictly fix CWE-208, the entire comparison logic is replaced with `hmac.compare_digest`.
    return hmac.compare_digest(submitted.encode(), expected.encode())
