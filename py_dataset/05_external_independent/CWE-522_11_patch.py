from pathlib import Path
import os
from cryptography.fernet import Fernet


def save_client_settings(settings_model) -> None:
    # Retrieve the encryption key from environment variables.
    # This key must be securely managed and is crucial for data security.
    # Fernet requires a URL-safe base64-encoded 32-byte key.
    # If the environment variable is not set, a KeyError will be raised,
    # which is an appropriate failure mode for missing security configuration.
    encryption_key_bytes = os.environ["CLIENT_SETTINGS_ENCRYPTION_KEY"].encode("utf-8")

    # Initialize Fernet with the encryption key.
    f = Fernet(encryption_key_bytes)

    # Dump the model to JSON string, then encode to bytes for encryption.
    sensitive_data_json_bytes = settings_model.model_dump_json().encode("utf-8")

    # Encrypt the sensitive data.
    encrypted_data = f.encrypt(sensitive_data_json_bytes)

    # Write the encrypted data (bytes) to the file.
    # Use 'write_bytes' as the data is now binary encrypted content,
    # removing the plaintext storage vulnerability (CWE-522).
    Path("client-settings.json").write_bytes(encrypted_data)
