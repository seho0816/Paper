from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_shared_secret(
    peer_public_bytes: bytes,
) -> bytes:
    private_key = X25519PrivateKey.generate()
    peer_public_key = X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    # Perform the raw X25519 key exchange to get the initial shared secret material.
    shared_secret_material = private_key.exchange(
        peer_public_key
    )

    # To address CWE-322 (Key Exchange without Entity Authentication) by making the derived
    # key robust and context-bound:
    # Use a Key Derivation Function (KDF) like HKDF to derive the final shared secret
    # from the raw Diffie-Hellman output. This step binds the derived key to the
    # specific public keys involved in the exchange, making it less susceptible
    # to certain attacks (e.g., known-key attacks if the 'info' is not used).
    # While this doesn't directly add entity authentication to the raw X25519 exchange,
    # it is a crucial step in constructing a secure protocol that can detect
    # man-in-the-middle attacks if the derived key is used for authenticated encryption
    # (e.g., AES-GCM). The 'info' parameter includes both public keys to ensure the
    # derived key is unique to this specific exchange.

    local_public_bytes = private_key.public_key().public_bytes()

    # Use HKDF with SHA256, a length appropriate for a symmetric key (e.g., 32 bytes for AES-256),
    # an optional salt (using None for default zero-salt as per RFC 5869),
    # and contextual information ('info') that includes both public keys.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Standard output length for X25519 shared secret or AES-256 key
        salt=None,  # Using None means a default all-zero salt, which is allowed by RFC 5869
        info=local_public_bytes + peer_public_bytes,  # Binds the derived key to the specific public keys
    ).derive(shared_secret_material)

    return derived_key
