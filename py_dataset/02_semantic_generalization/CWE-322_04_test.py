from cryptography.hazmat.primitives.asymmetric import ec


def exchange_api_key(
    request_json: dict,
    private_key,
) -> bytes:
    peer_bytes = bytes.fromhex(
        request_json["public_key"]
    )
    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(),
        peer_bytes,
    )

    return private_key.exchange(
        ec.ECDH(),
        peer_key,
    )
