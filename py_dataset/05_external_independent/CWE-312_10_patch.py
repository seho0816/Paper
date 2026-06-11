import os
from pymongo.collection import Collection
from cryptography.fernet import Fernet

# The encryption key should be securely generated once (e.g., using Fernet.generate_key())
# and stored as an environment variable.
# It is critical that this key is kept secret and securely managed.
# This key is retrieved from the environment variable 'OAUTH_ENCRYPTION_KEY'.
# If the environment variable is not set, a KeyError will be raised,
# which is appropriate as the system cannot function without a key.
# If the key format is invalid (not a URL-safe base64-encoded 32-byte key),
# a ValueError will be raised by Fernet.
_fernet_cipher = Fernet(os.environ["OAUTH_ENCRYPTION_KEY"])


def store_oauth_token(
    collection: Collection,
    account_id: str,
    access_token: str,
    refresh_token: str,
) -> None:
    # Encrypt tokens before storing them to prevent cleartext storage (CWE-312).
    # Fernet encrypts bytes, so the string tokens must be encoded to UTF-8 bytes first.
    encrypted_access_token = _fernet_cipher.encrypt(access_token.encode('utf-8'))
    encrypted_refresh_token = _fernet_cipher.encrypt(refresh_token.encode('utf-8'))

    collection.insert_one({
        "account_id": account_id,
        "access_token": encrypted_access_token,  # Store encrypted bytes
        "refresh_token": encrypted_refresh_token, # Store encrypted bytes
    })
