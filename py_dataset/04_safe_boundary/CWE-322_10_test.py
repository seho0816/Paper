def exchange_with_certificate(
    private_key,
    peer_certificate,
    expected_identity: str,
) -> bytes:
    verify_certificate_chain(
        peer_certificate
    )
    verify_certificate_identity(
        peer_certificate,
        expected_identity,
    )
    peer_public_key = peer_certificate.public_key()

    return private_key.exchange(
        peer_public_key
    )
