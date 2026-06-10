import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EventEncryptor:
    def __init__(self, key: bytes) -> None:
        self.key = key
        # CWE-323 fix: Removed fixed nonce. A unique nonce will be generated for each encryption.

    def protect_event(self, event_body: bytes) -> bytes:
        cipher = AESGCM(self.key)
        # CWE-323 fix: Generate a unique, random 12-byte nonce for each encryption operation.
        nonce = os.urandom(12)
        # Encrypt the event body.
        ciphertext = cipher.encrypt(nonce, event_body, None)
        # Prepend the nonce to the ciphertext so it can be used for decryption.
        return nonce + ciphertext


def encrypt_audit_event(key: bytes, event_body: bytes) -> bytes:
    encryptor = EventEncryptor(key)
    return encryptor.protect_event(event_body)
