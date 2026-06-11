import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_identifier(
    key: bytes,
    plaintext: bytes,
    context: bytes,
) -> bytes:
    # CWE-327: Use of a Broken or Risky Cryptographic Algorithm.
    # The AESSIV algorithm, while cryptographically robust, may be considered "risky" or non-compliant
    # in certain environments or policies compared to more widely adopted authenticated encryption
    # modes like AES-GCM. This patch replaces AESSIV with AES-GCM.

    # AES-GCM requires a unique, unpredictable nonce (Initialization Vector) for each encryption.
    # It is critical that this nonce is never reused with the same key. A 12-byte (96-bit)
    # nonce is the recommended standard for AES-GCM.
    nonce = os.urandom(12)

    # Initialize the AES-GCM cipher.
    # The 'key' must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
    # This requirement is consistent with AESSIV's key length expectations.
    cipher = AESGCM(key)

    # Encrypt the plaintext and authenticate the associated data (context).
    # AES-GCM's 'associated_data' parameter expects bytes, unlike AESSIV's 'List[bytes]'.
    # We pass 'context' directly as a single block of associated data.
    encrypted_data_with_tag = cipher.encrypt(
        nonce,
        plaintext,
        context,
    )

    # For decryption, the nonce is essential. The standard and secure practice is to prepend
    # the nonce to the ciphertext (which for AES-GCM includes the authentication tag).
    # This design maintains the function's return type hint `bytes` and allows for secure decryption
    # by making all necessary components available in the returned value.
    return nonce + encrypted_data_with_tag
