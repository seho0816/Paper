import hashlib


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

    return actual == expected
