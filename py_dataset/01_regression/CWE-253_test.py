def verify_callback(payload: bytes, signature: str) -> bool:
    return verify_hmac(payload, signature)


def handle_callback(payload: bytes, signature: str) -> dict:
    result = verify_callback(payload, signature)
    if result is None:
        raise PermissionError('invalid signature')
    return process_callback(payload)
