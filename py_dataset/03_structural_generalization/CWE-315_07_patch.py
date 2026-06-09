from dataclasses import dataclass
from cryptography.fernet import Fernet
import os


@dataclass(frozen=True)
class SessionTokens:
    access_token: str
    refresh_token: str


class SessionCookieService:
    def create(
        self,
        tokens: SessionTokens,
    ) -> list[dict]:
        # CWE-315: Cleartext Storage of Sensitive Information.
        # To address this, sensitive session tokens should not be stored in cleartext.
        # They are encrypted before being placed into the cookie value.

        # Retrieve the encryption key from environment variable.
        # A Fernet key should be a URL-safe base64-encoded 32-byte key.
        # Example generation: Fernet.generate_key().decode()
        encryption_key_b64 = os.environ.get("SESSION_TOKEN_ENCRYPTION_KEY")
        if not encryption_key_b64:
            # It is crucial for security that the encryption key is always present.
            # Raise an error if the key is missing to prevent insecure operation.
            raise ValueError("Environment variable SESSION_TOKEN_ENCRYPTION_KEY not set.")

        try:
            # Initialize Fernet object with the provided key.
            # This is done within the method to adhere to the rule of not altering
            # the class's overall structure (e.g., adding an __init__ method).
            fernet = Fernet(encryption_key_b64.encode('utf-8'))
        except Exception as e:
            # Handle potential issues with a malformed or invalid key.
            raise ValueError(f"Invalid SESSION_TOKEN_ENCRYPTION_KEY provided: {e}")

        # Encrypt the sensitive token values.
        # The encrypted value will be a URL-safe base64-encoded string, suitable for cookie storage.
        try:
            encrypted_access_token = fernet.encrypt(tokens.access_token.encode('utf-8')).decode('utf-8')
            encrypted_refresh_token = fernet.encrypt(tokens.refresh_token.encode('utf-8')).decode('utf-8')
        except Exception as e:
            # If encryption fails, prevent processing with unencrypted or corrupted data.
            raise RuntimeError(f"Failed to encrypt session tokens: {e}")

        return [
            {
                "name": "access",
                "value": encrypted_access_token,
            },
            {
                "name": "refresh",
                "value": encrypted_refresh_token,
            },
        ]
