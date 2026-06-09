from cryptography.hazmat.primitives.asymmetric import padding


class SessionKeyWrapper:
    def __init__(self, public_key) -> None:
        self.public_key = public_key

    def wrap_key(self, session_key: bytes) -> bytes:
        return self.public_key.encrypt(
            session_key,
            padding.PKCS1v15(),
        )


def encrypt_export_key(public_key, session_key: bytes) -> bytes:
    wrapper = SessionKeyWrapper(public_key)
    return wrapper.wrap_key(session_key)
