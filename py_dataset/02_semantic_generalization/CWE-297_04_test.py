import hashlib


def verify_peer(
    certificate_der: bytes,
    expected_fingerprint: str,
    requested_host: str,
) -> bool:
    actual_fingerprint = hashlib.sha256(
        certificate_der
    ).hexdigest()

    return (
        actual_fingerprint
        == expected_fingerprint
    )
