from pathlib import Path
import os
from cryptography.fernet import Fernet


def save_cli_profile(profile_name: str, access_key: str) -> None:
    profile_path = Path.home() / ".app" / "profiles" / profile_name
    profile_path.parent.mkdir(parents=True, exist_ok=True)

    # Retrieve encryption key from environment variable.
    # The key must be a URL-safe base64-encoded 32-byte key.
    # Example generation: Fernet.generate_key().decode('utf-8')
    # If 'APP_SECRET_KEY' is not set, os.environ.get will return None.
    # Attempting to call .encode('utf-8') on None will raise an AttributeError,
    # preventing insecure storage without a valid key.
    encryption_key_b64_str = os.environ.get("APP_SECRET_KEY")

    # The Fernet key must be bytes.
    f = Fernet(encryption_key_b64_str.encode('utf-8'))

    # Encrypt the access_key before writing it to the file.
    encrypted_access_key_bytes = f.encrypt(access_key.encode("utf-8"))

    # Write the base64-encoded encrypted access key to the file.
    # The output of Fernet.encrypt is bytes, which are already base64 encoded.
    # Decode these bytes to a UTF-8 string for write_text to store it as a string in the file.
    profile_path.write_text(
        "access_key=" + encrypted_access_key_bytes.decode("utf-8"),
        encoding="utf-8",
    )
