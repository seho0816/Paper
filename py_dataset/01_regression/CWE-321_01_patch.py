import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CWE-321: Hard-coded cryptographic key.
# The fix is to load the key from an environment variable instead of hardcoding it.
# It is assumed that the environment variable 'AES_ENCRYPTION_KEY' contains
# the 32-character string representing the 256-bit AES key.
# The .encode('ascii') method converts this string into the required bytes format.
# A KeyError will be raised if the environment variable is not set, preventing
# the application from running with a missing key.
AES_KEY = os.environ["AES_ENCRYPTION_KEY"].encode('ascii')


def encrypt_secret(secret: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(AES_KEY).encrypt(
        nonce,
        secret,
        None,
    )

    return nonce, ciphertext
