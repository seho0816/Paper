from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import osrandom


def encrypt_user_data(
    key: bytes,
    user_id: str,
    plaintext: bytes,
) -> bytes:
    # CWE-329: Not Using an Unpredictable IV with Symmetric Block Cipher in CBC Mode
    # The IV must be cryptographically random and unique for each encryption.
    # It should not be derived from predictable inputs like user_id.
    # For AES, the block size is 16 bytes.
    iv = osrandom.urandom(16)

    encryptor = Cipher(
        algorithms.AES(
            key
        ),
        modes.CBC(
            iv
        ),
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # The IV must be made available for decryption.
    # Following the strict rule of maintaining the function signature,
    # the IV is prepended to the ciphertext.
    return iv + ciphertext
