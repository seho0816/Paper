import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Assuming decode_ecdh_public_key is defined elsewhere and returns an
# ec.EllipticCurvePublicKey object or similar suitable for exchange.

def handle_device_key(
    message: dict,
) -> bytes:
    peer_key = decode_ecdh_public_key(
        message["public_key"]
    )

    # CWE-322 fix: To enable entity authentication for the device, a persistent
    # private key associated with the device's identity must be used instead
    # of generating a new ephemeral key on each call. This change allows
    # the device to establish a consistent identity for authentication purposes
    # in subsequent protocol steps (e.g., signing an ephemeral public key or data).
    try:
        device_private_key_pem = os.environ["DEVICE_PRIVATE_KEY_PEM"]
        private_key = serialization.load_pem_private_key(
            device_private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
    except KeyError:
        raise RuntimeError("Device private key not found in environment variable 'DEVICE_PRIVATE_KEY_PEM'. Cannot establish device identity for key exchange.")
    except ValueError as e:
        raise RuntimeError(f"Failed to load device private key: {e}. Ensure it is in valid PEM format.")

    return private_key.exchange(
        peer_key
    )
