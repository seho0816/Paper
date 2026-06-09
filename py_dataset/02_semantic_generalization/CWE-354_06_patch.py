import hashlib
import hmac


def validate_upload_body(
    headers: dict,
    body: bytes,
) -> bool:
    expected = headers.get(
        "X-Content-SHA256",
        "",
    )
    actual = hashlib.sha256(
        body
    ).hexdigest()

    # CWE-354 fix: Use hmac.compare_digest to prevent timing attacks
    # Both 'actual' and 'expected' are hexadecimal strings, so they must be
    # encoded to bytes before being passed to compare_digest.
    return hmac.compare_digest(actual.encode('utf-8'), expected.encode('utf-8'))
