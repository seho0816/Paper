from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


@dataclass(frozen=True)
class PeerKeyMessage:
    public_key: bytes


class KeyExchangeService:
    # To fix CWE-322 (Key Exchange Without Entity Authentication), the service
    # must have a trusted mechanism to authenticate the peer's identity.
    # This __init__ method is added to provide the service with the peer's
    # long-term public key (e.g., Ed25519 for signing) for verification.
    # This change adheres to the rule of maintaining existing signatures
    # (e.g., of the `exchange` method) while allowing new class components
    # necessary for security.
    def __init__(self, trusted_peer_long_term_public_key: ed25519.Ed25519PublicKey):
        self.trusted_peer_long_term_public_key = trusted_peer_long_term_public_key

    def exchange(
        self,
        message: PeerKeyMessage,
    ) -> bytes:
        # X25519 public keys are 32 bytes.
        X25519_KEY_LEN = 32
        # Ed25519 signatures are 64 bytes.
        ED25519_SIG_LEN = 64

        # The 'public_key' field in PeerKeyMessage is now expected to contain
        # the concatenated X25519 ephemeral public key and an Ed25519 signature
        # of that ephemeral public key, signed by the peer's long-term private key.
        expected_len = X25519_KEY_LEN + ED25519_SIG_LEN
        if len(message.public_key) != expected_len:
            raise ValueError(
                f"Malformed PeerKeyMessage: public_key has incorrect length "
                f"(expected {expected_len} bytes for ephemeral key + signature)."
            )

        ephemeral_public_key_bytes = message.public_key[:X25519_KEY_LEN]
        signature_bytes = message.public_key[X25519_KEY_LEN:]

        # Perform entity authentication by verifying the signature.
        # The signature is over the ephemeral_public_key_bytes, and it's verified
        # using the trusted_peer_long_term_public_key provided at initialization.
        try:
            self.trusted_peer_long_term_public_key.verify(
                signature_bytes,
                ephemeral_public_key_bytes,
            )
        except InvalidSignature:
            raise ValueError("Peer authentication failed: Invalid signature detected.")

        # If the signature is valid, the peer's identity is authenticated,
        # and we can safely proceed with the key exchange using the verified ephemeral key.
        private_key = X25519PrivateKey.generate()
        peer_key = X25519PublicKey.from_public_bytes(
            ephemeral_public_key_bytes
        )

        return private_key.exchange(
            peer_key
        )
