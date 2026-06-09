import hashlib


def resolve_verify_upload(
    _root,
    _info,
    content: bytes,
    sha256: str,
) -> dict:
    actual = hashlib.sha256(
        content
    ).hexdigest()

    return {
        "valid": actual == sha256,
    }
