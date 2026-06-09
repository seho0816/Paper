import hashlib


def create_release_digest(
    content: bytes,
) -> bytes:
    digest = hashlib.sha256(
        content
    )

    return digest.digest()
