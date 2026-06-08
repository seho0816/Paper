from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SessionCookieDecryptor:
    def __init__(self, encryption_key: bytes) -> None:
        self.encryption_key = encryption_key

    def decrypt(self, iv: bytes, encrypted_payload: bytes) -> bytes:
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_payload) + decryptor.finalize()
