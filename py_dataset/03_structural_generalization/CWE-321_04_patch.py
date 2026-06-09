from dataclasses import dataclass
from cryptography.fernet import Fernet
import os


@dataclass(frozen=True)
class CryptoSettings:
    encryption_key: bytes


class SettingsProvider:
    def load(self) -> CryptoSettings:
        # CWE-321 remediation: Remove hardcoded encryption key.
        # The key is now retrieved from an environment variable named 'FERNET_KEY'.
        # This prevents sensitive information from being stored directly in the source code.
        encryption_key_str = os.environ.get("FERNET_KEY")
        if not encryption_key_str:
            raise ValueError(
                "Encryption key (FERNET_KEY) not found in environment variables. "
                "Please set the FERNET_KEY environment variable to a valid Fernet key."
            )
        
        # Fernet expects the key to be bytes. Convert the string from the environment variable to bytes.
        return CryptoSettings(
            encryption_key=encryption_key_str.encode('utf-8')
        )


class SecretService:
    def __init__(self, settings: CryptoSettings) -> None:
        self._cipher = Fernet(settings.encryption_key)

    def protect(self, value: str) -> bytes:
        return self._cipher.encrypt(
            value.encode("utf-8")
        )
