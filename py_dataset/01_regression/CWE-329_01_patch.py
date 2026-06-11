import os
from Crypto.Cipher import AES


def encrypt_record(
    key: bytes,
    padded_record: bytes,
) -> bytes:
    # CWE-329: Not Using a Random IV with CBC Mode
    # The IV should be random and unique for each encryption,
    # and should not be derived from the encryption key.
    # Generate a cryptographically secure random 16-byte (for AES) IV.
    iv = os.urandom(16)
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    encrypted_data = cipher.encrypt(
        padded_record
    )

    # In CBC mode, the IV does not need to be secret but must be unique and unpredictable.
    # It is standard practice to prepend the IV to the ciphertext so that the decrypting party
    # can retrieve it for decryption. This adheres to the function's return type (bytes).
    return iv + encrypted_data
