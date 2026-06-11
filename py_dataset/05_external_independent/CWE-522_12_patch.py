import json
from pathlib import Path
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


def save_notebook_credential(notebook_path: Path, api_key: str) -> None:
    # Retrieve the master encryption key from an environment variable.
    # This key should be a strong, random string and managed securely (e.g., generated once
    # and stored in the environment of the application runtime).
    encryption_master_key_env = os.environ.get("NOTEBOOK_CREDENTIAL_ENCRYPTION_KEY")

    if not encryption_master_key_env:
        # CWE-522: Insufficiently Protected Credentials.
        # If no master encryption key is available, storing credentials would be insecure.
        # Raising an error prevents the insecure storage of the API key.
        raise ValueError(
            "NOTEBOOK_CREDENTIAL_ENCRYPTION_KEY environment variable is not set. "
            "Cannot store API key securely. Please set this environment variable "
            "with a strong, unique key for encryption."
        )

    # Convert the environment variable string into a bytes object for key derivation.
    master_key_bytes = encryption_master_key_env.encode('utf-8')

    # A fixed, application-specific salt is used to derive the Fernet key from the master key.
    # This salt is not a secret but ensures that the same master key always derives
    # the same Fernet key consistently, allowing for reliable encryption and decryption
    # across different sessions and multiple calls to this function.
    # This improves the security of the key derivation process against dictionary attacks
    # on the environment variable value.
    salt = b'notebook_credential_storage_application_salt_cwe522' 

    # Derive a Fernet-compatible key using PBKDF2HMAC.
    # PBKDF2HMAC provides key stretching, making it significantly harder to brute-force
    # the master key even if the environment variable value were to be relatively weak.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet keys are 32 bytes (256 bits)
        salt=salt,
        iterations=480000, # Recommended iteration count for PBKDF2 as of 2023 for general-purpose use
        backend=default_backend()
    )
    # The derived key must be URL-safe base64 encoded for use with Fernet.
    derived_fernet_key = base64.urlsafe_b64encode(kdf.derive(master_key_bytes))
    
    # Initialize Fernet with the securely derived key.
    f = Fernet(derived_fernet_key)

    # Encrypt the API key before storing it to address CWE-522.
    # The API key is converted to bytes for encryption and then back to a string (base64-encoded ciphertext) for storage.
    encrypted_api_key = f.encrypt(api_key.encode('utf-8')).decode('utf-8')

    sidecar = notebook_path.with_suffix(".credentials.json")
    sidecar.write_text(
        json.dumps({"api_key": encrypted_api_key}), # Store the encrypted API key
        encoding="utf-8",
    )
