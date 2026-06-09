from nacl.secret import SecretBox

SECRET_BOX_KEY = (
    b"0123456789abcdef0123456789abcdef"
)


def protect_payload(payload: bytes) -> bytes:
    box = SecretBox(SECRET_BOX_KEY)
    return box.encrypt(payload)
