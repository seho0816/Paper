import os
from cryptography.hazmat.primitives.asymmetric import ec


def exchange_api_key(
    request_json: dict,
    private_key,
) -> bytes:
    peer_bytes = bytes.fromhex(
        request_json["public_key"]
    )

    expected_peer_public_key_hex = os.environ.get("EXPECTED_PEER_PUBLIC_KEY_HEX")

    if not expected_peer_public_key_hex:
        raise ValueError("EXPECTED_PEER_PUBLIC_KEY_HEX environment variable is not set.")

    if peer_bytes.hex() != expected_peer_public_key_hex:
        raise ValueError("Provided public key does not match the expected peer public key.")

    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(),
        peer_bytes,
    )

    return private_key.exchange(
        ec.ECDH(),
        peer_key,
    )
