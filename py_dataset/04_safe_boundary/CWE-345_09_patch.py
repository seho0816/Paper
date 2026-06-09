from cryptography.exceptions import InvalidSignature


def verify_event(
    public_key,
    event_body: bytes,
    signature: bytes,
) -> bool:
    try:
        public_key.verify(
            signature,
            event_body,
        )
    except InvalidSignature:
        return False

    return True

