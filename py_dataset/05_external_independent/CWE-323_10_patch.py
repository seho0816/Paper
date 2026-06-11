import os
from Crypto.Cipher import AES


def encrypt_document(
    key: bytes,
    document: bytes,
) -> tuple[bytes, bytes]:
    # CWE-323 (or more accurately, CWE-330/CWE-340): Using a static nonce
    # A static or hardcoded nonce leads to nonce reuse, which is a critical
    # cryptographic vulnerability in AES-GCM, compromising confidentiality and
    # authentication if the same key and nonce are used for multiple encryptions.
    # The nonce must be unique for each encryption operation under the same key.
    # Generate a cryptographically secure random nonce (12 bytes for GCM).
    nonce = os.urandom(12)
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
    )
    ciphertext, tag = cipher.encrypt_and_digest(
        document
    )

    # To maintain the original return signature (tuple[bytes, bytes]),
    # the nonce is prepended to the ciphertext. The decryption function
    # would need to extract the nonce from the beginning of this combined byte string.
    return nonce + ciphertext, tag
