import os
from dataclasses import dataclass
from cryptography.fernet import Fernet


@dataclass(frozen=True)
class IntegrationCredential:
    integration_id: str
    api_secret: str


class CredentialCache:
    def __init__(
        self,
        redis_client,
    ) -> None:
        self._redis = redis_client
        # Retrieve encryption key from an environment variable to avoid hardcoding.
        # This key must be securely generated and managed outside the application.
        encryption_key_b64 = os.environ.get("ENCRYPTION_KEY")
        if not encryption_key_b64:
            raise ValueError("ENCRYPTION_KEY environment variable not set or is empty.")
        self._fernet = Fernet(encryption_key_b64)

    def put(
        self,
        credential: IntegrationCredential,
    ) -> None:
        # Encrypt the api_secret before storing it to prevent cleartext storage (CWE-312).
        # Fernet operates on bytes, so the string secret must be encoded first.
        encrypted_secret = self._fernet.encrypt(credential.api_secret.encode('utf-8'))
        self._redis.hset(
            f"integration:{credential.integration_id}",
            mapping={
                "api_secret": encrypted_secret,  # Store the encrypted bytes
            },
        )
