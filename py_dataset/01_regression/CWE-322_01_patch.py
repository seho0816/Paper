from cryptography.hazmat.primitives.asymmetric import ec


def derive_ecdh_secret(
    private_key,
    peer_public_key_bytes: bytes,
) -> bytes:
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        private_key.curve,  # CWE-322 mitigation: Ensure peer public key is on the same curve as the private key
        peer_public_key_bytes,
    )

    return private_key.exchange(
        ec.ECDH(),
        peer_public_key,
    )
