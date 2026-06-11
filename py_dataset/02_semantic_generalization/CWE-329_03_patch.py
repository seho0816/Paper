import hashlib
import os
from datetime import date

from Crypto.Cipher import AES


def encrypt_daily_export(
    key: bytes,
    content: bytes,
) -> bytes:
    # CWE-329 fix: Replace predictable IV generation with a cryptographically secure random IV.
    # The original IV was derived from the current date, making it predictable.
    # A random IV ensures that identical plaintexts produce different ciphertexts,
    # and prevents attacks like known-plaintext attacks from being trivial.
    iv = os.urandom(16)  # Generate a 16-byte (128-bit) random IV for AES

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    encrypted_content = cipher.encrypt(
        content
    )

    # Prepend the IV to the ciphertext. The IV does not need to be secret,
    # but it must be unique and unpredictable for each encryption.
    # It is required for decryption.
    return iv + encrypted_content
