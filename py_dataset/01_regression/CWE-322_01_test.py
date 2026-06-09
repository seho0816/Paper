from cryptography.hazmat.primitives.asymmetric import ec


def derive_ecdh_secret(
    private_key,
    peer_public_key_bytes: bytes,
) -> bytes:
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_key_bytes,
    )

    return private_key.exchange(
        ec.ECDH(),
        peer_public_key,
    )
