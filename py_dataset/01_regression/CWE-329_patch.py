import os
from Crypto.Cipher import AES


def encrypt_profile(
    data: bytes,
    key: bytes,
) -> bytes:
    # CWE-329: Not Using an Unpredictable IV with Symmetric Block Cipher in CBC Mode
    # Generate a random, unpredictable IV for each encryption.
    # The IV size must match the cipher's block size (16 bytes for AES).
    iv = os.urandom(AES.block_size)
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    return cipher.encrypt(
        data
    )
