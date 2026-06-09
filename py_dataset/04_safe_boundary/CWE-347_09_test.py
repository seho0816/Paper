from cryptography.exceptions import InvalidSignature


def verify_message(
    public_key,
    message: bytes,
    signature: bytes,
) -> bool:
    try:
        public_key.verify(
            signature,
            message,
        )
    except InvalidSignature:
        return False

    return True
