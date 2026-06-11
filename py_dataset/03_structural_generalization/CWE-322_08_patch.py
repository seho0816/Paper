from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def derive_channel_key(shared_secret: bytes) -> bytes:
    """
    Derives a cryptographically strong channel key from a shared secret
    using HKDF-SHA256, following best practices for key derivation to prevent
    CWE-322 related vulnerabilities (e.g., insufficient entropy in derived keys
    or weak derivation processes).
    """
    # HKDF is used to deterministically derive a high-entropy key from the shared secret.
    # - algorithm: SHA256 is a strong cryptographic hash function.
    # - length: 32 bytes (256 bits) is a standard length for a strong symmetric key.
    # - salt: None is used here, assuming the 'shared_secret' itself is already
    #   high-entropy and unique per key exchange (e.g., from ECDH). In protocols
    #   where a session-unique salt (e.g., from nonces) is available, it should be used.
    # - info: This parameter provides domain separation, ensuring that the derived
    #   key is specifically bound to its intended purpose ("channel key derivation").
    #   This helps prevent cross-protocol attacks or misuse of keys.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"channel key derivation",
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


@dataclass(frozen=True)
class ChannelRequest:
    peer_public_key: object


class SecureChannelFactory:
    def __init__(
        self,
        private_key,
    ) -> None:
        self._private_key = private_key

    def create(
        self,
        request: ChannelRequest,
    ) -> bytes:
        shared_secret = self._private_key.exchange(
            request.peer_public_key
        )

        return derive_channel_key(
            shared_secret
        )
