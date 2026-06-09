from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EventEncryptor:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.nonce = b"fixed-nonce!"

    def protect_event(self, event_body: bytes) -> bytes:
        cipher = AESGCM(self.key)
        return cipher.encrypt(self.nonce, event_body, None)


def encrypt_audit_event(key: bytes, event_body: bytes) -> bytes:
    encryptor = EventEncryptor(key)
    return encryptor.protect_event(event_body)
