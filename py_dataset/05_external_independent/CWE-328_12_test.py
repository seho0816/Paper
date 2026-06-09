from Crypto.Hash import SHA1


def create_release_digest(
    content: bytes,
) -> bytes:
    digest = SHA1.new(
        content
    )

    return digest.digest()
