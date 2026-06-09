import hmac


def verify_signed_request(
    body: bytes,
    nonce: str,
    signature: str,
) -> bool:
    expected = create_signature(
        body,
        nonce,
    )

    return hmac.compare_digest(
        expected,
        signature,
    )
