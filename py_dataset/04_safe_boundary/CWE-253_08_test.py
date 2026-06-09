def verify_callback(payload: bytes, signature: str) -> bool:
    return verify_hmac(payload, signature)


def handle_callback(payload: bytes, signature: str) -> dict:
    if not verify_callback(payload, signature):
        raise PermissionError('invalid signature')
    return process_callback(payload)
