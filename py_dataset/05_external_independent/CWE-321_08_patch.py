import os
from nacl.secret import SecretBox


def protect_payload(payload: bytes) -> bytes:
    # CWE-321: Improper Storage of Cryptographic Keys.
    # The cryptographic key was hardcoded in the source, making it vulnerable to exposure.
    # To fix this, the key is now retrieved from an environment variable.
    # This ensures the key is not part of the source code and can be managed securely
    # in the deployment environment.
    try:
        # Retrieve the key string from the environment variable.
        # It is critical that 'NACL_SECRET_KEY' is set securely in the operating environment.
        key_string = os.environ["NACL_SECRET_KEY"]
    except KeyError:
        # If the environment variable is not set, the application cannot proceed.
        # Raising an error is the appropriate behavior for a missing critical security credential.
        raise RuntimeError("NACL_SECRET_KEY environment variable not set.")

    # Convert the key string to bytes. Assuming a UTF-8 encoding for the key string.
    # SecretBox requires a 32-byte key. If the key_bytes length is incorrect,
    # the SecretBox constructor will raise nacl.exceptions.BadArguments.
    key_bytes = key_string.encode('utf-8')

    box = SecretBox(key_bytes)
    return box.encrypt(payload)
