import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_legacy_note(
    note: bytes,
) -> bytes:
    key = os.environ["BLOWFISH_KEY"].encode("utf-8")
    # For AES, the key must be 16, 24, or 32 bytes long.
    # The original code did not perform key length validation or derivation.
    # It is assumed that the environment variable "BLOWFISH_KEY" will now
    # provide a key of appropriate length for AES, or that key derivation
    # is handled externally before being set in the environment.

    cipher = AES.new(
        key,
        AES.MODE_GCM,  # Replaced Blowfish and ECB mode with AES in GCM mode
    )

    padded_note = pad(
        note,
        AES.block_size,  # Updated block size to AES.block_size
    )

    ciphertext, tag = cipher.encrypt_and_digest(padded_note)

    # For AES GCM, the nonce, ciphertext, and authentication tag are all
    # necessary for secure decryption and integrity verification.
    # They are concatenated here to maintain the function's original return type (bytes).
    return cipher.nonce + ciphertext + tag
