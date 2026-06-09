import json
from pathlib import Path
import os
from cryptography.fernet import Fernet
import base64


def save_refresh_token(account_id: str, refresh_token: str) -> None:
    # Retrieve the Fernet encryption key from an environment variable.
    # This key should be a URL-safe base64 encoded string.
    # Example: os.environ["REFRESH_TOKEN_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    fernet_key_str = os.environ["REFRESH_TOKEN_ENCRYPTION_KEY"]

    # Decode the base64 key string to bytes, as Fernet expects a bytes object.
    fernet_key = base64.urlsafe_b64decode(fernet_key_str)

    f = Fernet(fernet_key)

    # Encrypt the refresh_token. Fernet expects bytes for encryption,
    # and returns bytes (which are base64 encoded ciphertext).
    # We decode these bytes to a UTF-8 string to store them easily in JSON.
    encrypted_refresh_token = f.encrypt(refresh_token.encode('utf-8')).decode('utf-8')

    path = Path.home() / ".session_credentials.json"
    path.write_text(
        json.dumps({
            "account_id": account_id,
            "refresh_token": encrypted_refresh_token,  # Store the encrypted token
        }),
        encoding="utf-8",
    )
