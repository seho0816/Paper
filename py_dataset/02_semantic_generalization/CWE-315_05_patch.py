import json
import os
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidKey

# Retrieve the secret key from an environment variable.
# This key MUST be securely generated and stored (e.g., as a 32 URL-safe base64-encoded bytes string).
# Example generation for a new key: Fernet.generate_key().decode('utf-8')
# If 'COOKIE_SECRET_KEY' is not set, this will raise a KeyError, which is an
# appropriate startup failure for missing critical configuration.
_FERNET_KEY_STR = os.environ["COOKIE_SECRET_KEY"]

# Initialize Fernet cipher suite globally for efficiency.
# Fernet expects a URL-safe base64-encoded 32-byte key as bytes.
# The key from os.environ is a string, so it needs to be encoded to bytes.
# If _FERNET_KEY_STR is not a valid Fernet key (e.g., wrong length, invalid base64),
# Fernet() will raise an InvalidKey exception during script loading.
try:
    _fernet_cipher = Fernet(_FERNET_KEY_STR.encode('utf-8'))
except InvalidKey as e:
    # In a real application, logging this critical error and exiting would be appropriate.
    # For this isolated code, we allow the exception to propagate, signifying a configuration issue.
    raise RuntimeError(f"Invalid Fernet key provided in COOKIE_SECRET_KEY: {e}") from e


def build_checkout_cookie(
    email: str,
    card_token: str,
) -> str:
    # Original sensitive data to be stored.
    data_to_protect = {
        "email": email,
        "card_token": card_token,
    }

    # Convert the dictionary to a JSON string and then to bytes for encryption.
    data_bytes = json.dumps(data_to_protect).encode('utf-8')

    # Encrypt the data using the globally initialized Fernet cipher.
    # Fernet provides authenticated encryption, protecting against both disclosure and tampering.
    encrypted_data = _fernet_cipher.encrypt(data_bytes)

    # Return the URL-safe base64 encoded encrypted data as a string.
    # Fernet.encrypt returns bytes, which needs to be decoded to a string for cookie storage.
    return encrypted_data.decode('utf-8')
