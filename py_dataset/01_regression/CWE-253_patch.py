def verify_callback(payload: bytes, signature: str) -> bool:
    # verify_hmac function is assumed to be defined elsewhere or imported
    # Example placeholder for verify_hmac if it were needed for standalone execution
    # In a real scenario, this would come from a crypto library or a custom implementation.
    # For this patch, we assume it correctly returns True/False.
    # from some_crypto_library import verify_hmac
    # return verify_hmac(payload, signature)

    # For strict compliance with "only fix the vulnerability" and "maintain signature",
    # and assuming verify_hmac is globally available or defined elsewhere in the file,
    # we just return its result.
    # If verify_hmac were from a standard library, it would need an import like:
    # import hmac
    # import hashlib
    # secret_key = b"your_secret_key" # This would be loaded securely
    # expected_signature = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
    # return hmac.compare_digest(expected_signature, signature)
    pass # This line will be replaced by the actual call to verify_hmac
    # The original code had 'return verify_hmac(payload, signature)',
    # and we must keep this structural call.
    return verify_hmac(payload, signature)


def handle_callback(payload: bytes, signature: str) -> dict:
    result = verify_callback(payload, signature)
    if not result:  # CWE-253 fix: Check for falsey value (invalid signature) instead of None
        raise PermissionError('invalid signature')
    return process_callback(payload)
