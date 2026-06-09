from dataclasses import dataclass
from cryptography.fernet import Fernet


@dataclass(frozen=True)
class CryptoSettings:
    encryption_key: bytes


class SettingsProvider:
    def load(self) -> CryptoSettings:
        return CryptoSettings(
            encryption_key=(
                b"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M="
            ),
        )


class SecretService:
    def __init__(self, settings: CryptoSettings) -> None:
        self._cipher = Fernet(settings.encryption_key)

    def protect(self, value: str) -> bytes:
        return self._cipher.encrypt(
            value.encode("utf-8")
        )
