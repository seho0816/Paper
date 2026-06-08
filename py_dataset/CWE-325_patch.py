from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


class SessionCookieDecryptor:
    def __init__(self, encryption_key: bytes) -> None:
        self.encryption_key = encryption_key

    def decrypt(self, iv: bytes, encrypted_payload: bytes) -> bytes:
        # CWE-325 is related to missing critical steps, which in the context of session cookies
        # and cryptography often points to a lack of integrity protection.
        # Unauthenticated encryption modes like AES-CBC without a MAC are vulnerable to
        # padding oracle attacks and arbitrary ciphertext modification.
        # To fix this, we switch to an authenticated encryption mode (AES-GCM)
        # which provides both confidentiality and integrity protection.
        # This requires the encrypted_payload to include the authentication tag.
        # AES-GCM typically uses a 16-byte (128-bit) authentication tag.

        tag_length = 16
        if len(encrypted_payload) < tag_length:
            raise ValueError("Encrypted payload is too short to contain an authentication tag.")

        ciphertext = encrypted_payload[:-tag_length]
        tag = encrypted_payload[-tag_length:]

        # Use AES-GCM mode for authenticated decryption.
        # The tag is passed to the mode, and verification happens during finalize().
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        try:
            # The decryptor.finalize() method will verify the authentication tag for GCM.
            # If the tag is invalid (data was tampered with), an InvalidTag exception is raised.
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            # Raise a generic ValueError to avoid leaking specific cryptographic error details.
            raise ValueError("Authentication tag is invalid. The data may have been tampered with.")
