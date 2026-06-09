from dataclasses import dataclass


@dataclass
class SigningKey:
    key_id: str
    secret: bytes
    expires_at: str


class DownloadLinkSigner:
    def __init__(self, keys: list[SigningKey]) -> None:
        self.keys = keys

    def sign(self, object_key: str) -> str:
        selected_key = self.keys[0]
        signature = create_signature(object_key, selected_key.secret)
        return f"{object_key}?kid={selected_key.key_id}&sig={signature}"


def create_signature(value: str, secret: bytes) -> str:
    return f"{value}:{secret.hex()}"
