import hmac

def verify_authentication_code(
    submitted_code: str,
    expected_code: str,
) -> bool:
    return hmac.compare_digest(
        submitted_code.encode('utf-8'),
        expected_code.encode('utf-8')
    )
