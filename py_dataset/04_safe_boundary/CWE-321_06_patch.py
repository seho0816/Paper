import base64
import os

from cryptography.fernet import Fernet


def load_cipher() -> Fernet:
    encoded_key = os.environ.get(
        "APPLICATION_ENCRYPTION_KEY"
    )

    if not encoded_key:
        raise RuntimeError(
            "encryption key is not configured"
        )

    # CWE-321 Fix: The original code had a potential cryptographic misuse
    # where the key from the environment variable might have been intended
    # as a raw 32-byte key, but was then incorrectly handled.
    # Specifically, `Fernet` expects a URL-safe base64-encoded key.
    # If `APPLICATION_ENCRYPTION_KEY` stores the raw 32 bytes (as a string),
    # the original code would try to base64-decode it (which is incorrect)
    # and then pass the raw string (encoded to bytes) to `Fernet`,
    # causing `Fernet` to attempt to base64-decode the raw bytes, leading
    # to a cryptographically broken key.

    # To fix this, we ensure that:
    # 1. 'decoded_key' correctly represents the raw 32-byte key.
    #    (Assuming 'encoded_key' from environment is the string form of raw bytes.)
    # 2. This raw key is then properly URL-safe base64-encoded before
    #    being passed to the Fernet constructor.

    # Convert the string from the environment variable to its raw byte representation.
    # Using 'latin-1' encoding to handle all possible byte values correctly if the key is truly raw.
    decoded_key = encoded_key.encode("latin-1")

    if len(decoded_key) != 32:
        raise RuntimeError(
            "invalid encryption key length"
        )

    # Encode the raw 32-byte key into a URL-safe base64 string (as bytes)
    # which is the format Fernet expects for its key.
    fernet_key_material = base64.urlsafe_b64encode(decoded_key)

    return Fernet(fernet_key_material)
