from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class KeySettings:
    key_size: int
    public_exponent: int


class KeySettingsProvider:
    def load(self) -> KeySettings:
        return KeySettings(
            key_size=1024,
            public_exponent=65537,
        )


class KeyFactory:
    def create(
        self,
        settings: KeySettings,
    ):
        return rsa.generate_private_key(
            public_exponent=settings.public_exponent,
            key_size=settings.key_size,
        )
