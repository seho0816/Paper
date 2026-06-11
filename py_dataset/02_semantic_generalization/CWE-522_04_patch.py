import sqlite3
import os
from cryptography.fernet import Fernet


def save_integration_credential(db_path: str, integration_id: str, secret: str) -> None:
    # CWE-522 fix: Ensure credentials are not stored in plaintext.
    # The 'secret' is encrypted using Fernet before being stored in the database.
    # The encryption key must be securely stored in an environment variable (FERNET_KEY).
    # This key should be a URL-safe base64-encoded 32-byte key, typically generated
    # once using Fernet.generate_key().
    try:
        encryption_key_bytes = os.environ["FERNET_KEY"].encode('utf-8')
        cipher_suite = Fernet(encryption_key_bytes)
    except KeyError:
        raise ValueError("FERNET_KEY environment variable is not set. Please set it to a valid Fernet key.")
    except Exception as e:
        raise ValueError(f"Failed to initialize Fernet cipher. Ensure FERNET_KEY is valid: {e}")

    # Encrypt the secret. Fernet expects bytes and outputs URL-safe base64 encoded bytes.
    encrypted_secret = cipher_suite.encrypt(secret.encode('utf-8'))

    connection = sqlite3.connect(db_path)
    connection.execute(
        "INSERT OR REPLACE INTO credentials(integration_id, secret) VALUES (?, ?)",
        (integration_id, encrypted_secret),  # Store the encrypted secret
    )
    connection.commit()
    connection.close()
