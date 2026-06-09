import os
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Placeholder/Helper functions for a complete, runnable code block ---
# These would typically be part of a larger application or cryptographic library.
# They are included here to make the provided code block self-contained and runnable.

def load_x25519_public_key(public_key_bytes):
    """
    Loads an X25519 public key from bytes.
    In a real system, more robust validation (e.g., checking for all-zero keys) might be needed.
    """
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        raise ValueError("Invalid X25519 public key bytes format or length.")
    return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

def generate_x25519_private_key():
    """
    Generates a new X25519 private key.
    """
    return x25519.X25519PrivateKey.generate()

def derive_channel_key(shared_secret):
    """
    Derives a channel key from the shared secret using HKDF.
    """
    # Use a unique, random salt for each key derivation to enhance security.
    # The 'info' parameter provides context for key separation.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),  # Use a random salt for better key separation
        info=b"channel key derivation context",
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

class AuthenticationError(Exception):
    """Custom exception for authentication failures during key exchange."""
    pass

# --- Authentication specific helper functions for CWE-322 fix ---
# These functions simulate a trusted source for peer signing keys.
# In a real application, this would involve a secure database, PKI, or configuration
# to retrieve trusted long-term public keys for known peers.

# For demonstration, a sample Ed25519 public key is hardcoded. In a production system,
# these keys would be securely loaded from configuration, environment variables,
# or a trusted key management system.
# This specific key is generated once for example purposes and is a concrete value,
# not a placeholder string like 'your_token_here'.
_TRUSTED_PEER_SIGNING_KEYS = {
    b"client_alice": ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex('e7b9e64e5210e53a2b724f8d3d92c7304f5e714b62d8c36b9e592e3a1f81c9a6')
    ),
    # Add other trusted peer keys as needed in a real application
}

def _get_peer_signing_public_key(peer_id_bytes):
    """
    Retrieves the trusted long-term Ed25519 public key for a given peer ID.
    Raises ValueError if the peer ID is unknown or untrusted.
    """
    if not isinstance(peer_id_bytes, bytes):
        raise TypeError("Peer ID must be bytes.")
    signing_key = _TRUSTED_PEER_SIGNING_KEYS.get(peer_id_bytes)
    if signing_key is None:
        raise ValueError(f"Unknown or untrusted peer ID: {peer_id_bytes.decode(errors='ignore')}")
    return signing_key

# --- End of helper functions ---


class KeyService:
    def Exchange(
        self,
        request,
        context,
    ):
        peer_key_bytes = request.public_key
        peer_key = load_x25519_public_key(peer_key_bytes)

        # CWE-322: Key Exchange without Entity Authentication
        # FIX: Introduce entity authentication by verifying the peer's ephemeral public key.
        # This requires the peer to sign their ephemeral public key with their long-term
        # private key, and for the request to include this signature and a peer identifier.
        # This implementation assumes the 'request' object provides:
        # - 'peer_id': An identifier for the peer (e.g., b"client_alice").
        # - 'ephemeral_key_signature': The digital signature of `request.public_key`
        #   created by the peer's long-term private (Ed25519) key.
        try:
            peer_id = request.peer_id
            ephemeral_key_signature = request.ephemeral_key_signature

            # 1. Retrieve the peer's trusted long-term public key (e.g., Ed25519).
            #    This key must be pre-provisioned or fetched via a trusted PKI.
            peer_signing_public_key = _get_peer_signing_public_key(peer_id)

            # 2. Verify the signature of the ephemeral X25519 public key.
            #    The message signed is `peer_key_bytes` (the raw bytes of the X25519 public key).
            peer_signing_public_key.verify(ephemeral_key_signature, peer_key_bytes)

        except AttributeError as e:
            # Catches if request.peer_id or request.ephemeral_key_signature are missing.
            raise AuthenticationError(f"Peer authentication failed: Missing required attribute in request: {e}")
        except InvalidSignature:
            # The signature verification failed, indicating the key is not from the claimed peer,
            # or the key has been tampered with.
            raise AuthenticationError("Peer authentication failed: Invalid ephemeral key signature")
        except (ValueError, TypeError) as e:
            # Catches errors during key retrieval (_get_peer_signing_public_key) or other data issues.
            raise AuthenticationError(f"Peer authentication failed: {e}")

        # If execution reaches this point, the peer's ephemeral public key has been
        # successfully authenticated and bound to its long-term identity.
        private_key = generate_x25519_private_key()
        shared_secret = private_key.exchange(
            peer_key
        )

        return {
            "channel_key": derive_channel_key(
                shared_secret
            ),
        }
