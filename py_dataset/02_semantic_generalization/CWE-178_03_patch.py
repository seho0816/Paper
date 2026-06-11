import hmac

def verify_recovery_code(
    submitted_code: str,
    expected_code: str,
) -> bool:
    normalized_submitted = (
        submitted_code.strip().upper()
    )
    normalized_expected = (
        expected_code.strip().upper()
    )

    # CWE-178 fix: Use hmac.compare_digest for constant-time comparison
    # to prevent timing attacks, ensuring data discrepancies are handled securely.
    # The strings must be encoded to bytes for compare_digest.
    return hmac.compare_digest(
        normalized_submitted.encode('utf-8'),
        normalized_expected.encode('utf-8')
    )
