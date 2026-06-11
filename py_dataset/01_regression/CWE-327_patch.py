import os
import hashlib
from Crypto.Cipher import AES


def encrypt_message(message: bytes) -> bytes:
    # CWE-327 fix: Replace DES (Data Encryption Standard) with AES (Advanced Encryption Standard).
    # DES is considered cryptographically weak due to its small key size and known vulnerabilities.
    #
    # Additionally, replace DES.MODE_ECB with AES.MODE_GCM.
    # ECB mode is insecure as it encrypts identical plaintext blocks into identical ciphertext blocks,
    # revealing patterns in the data. GCM (Galois/Counter Mode) provides authenticated encryption,
    # ensuring both confidentiality and integrity/authenticity of the data.

    # The original key was expected to be 8 bytes for DES. AES requires a key of 16, 24, or 32 bytes.
    # To securely derive an AES key from the `DES_KEY` environment variable (which might be too short),
    # we use SHA256 to hash the environment variable's content and truncate it to 16 bytes for AES-128.
    # This ensures a fixed-size, cryptographically strong key for AES.
    key_material = os.environ["DES_KEY"].encode("utf-8")
    key = hashlib.sha256(key_material).digest()[:16]  # Derived 16-byte key for AES-128

    # Initialize AES cipher in GCM mode.
    # AES.MODE_GCM automatically generates a unique nonce (number used once) for each encryption operation.
    cipher = AES.new(key, AES.MODE_GCM)

    # Encrypt the message. AES-GCM handles arbitrary length messages and does not require explicit padding
    # like the original DES.MODE_ECB implementation.
    ciphertext, tag = cipher.encrypt_and_digest(message)

    # The original function returned bytes. For AES-GCM, the nonce, ciphertext, and authentication tag
    # are all necessary for decryption and verification.
    # They are concatenated here to maintain the function's signature and return type.
    return cipher.nonce + ciphertext + tag
