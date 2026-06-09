from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


@dataclass(frozen=True)
class PeerKeyMessage:
    public_key: bytes


class KeyExchangeService:
    def exchange(
        self,
        message: PeerKeyMessage,
    ) -> bytes:
        private_key = X25519PrivateKey.generate()
        peer_key = X25519PublicKey.from_public_bytes(
            message.public_key
        )

        return private_key.exchange(
            peer_key
        )
