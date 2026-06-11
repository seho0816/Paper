import os

from Crypto.Cipher import AES


def encrypt_private_note(
    key: bytes,
    password_hash: str,
    padded_note: bytes,
) -> bytes:
    # CWE-329: Not Using an Initialization Vector (IV) or Using a Predictable IV
    # The original code derived the IV from 'password_hash', making it predictable
    # if the 'password_hash' is static or reused for multiple encryptions with the same key.
    # This predictability can lead to serious security vulnerabilities in CBC mode.

    # Fix: Generate a cryptographically secure, random IV for each encryption operation.
    # The IV must be unique and unpredictable for each encryption.
    # AES.block_size is 16 bytes for AES, which is the required IV length for AES in CBC mode.
    iv = os.urandom(AES.block_size)

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    # For decryption, the IV is required. It is standard practice to prepend the IV
    # to the ciphertext so that the recipient can extract it and use it for decryption.
    # The function's return type remains 'bytes' as per the strict rules.
    return iv + cipher.encrypt(
        padded_note
    )
