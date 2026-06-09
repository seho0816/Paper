import hashlib


def verify_certificate_pin(
    certificate_der: bytes,
    expected_pin: str,
) -> bool:
    actual_pin = hashlib.sha1(
        certificate_der
    ).hexdigest()

    return (
        actual_pin
        == expected_pin
    )
