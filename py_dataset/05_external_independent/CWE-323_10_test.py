from Crypto.Cipher import AES


def encrypt_document(
    key: bytes,
    document: bytes,
) -> tuple[bytes, bytes]:
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=b"document-non",
    )
    ciphertext, tag = cipher.encrypt_and_digest(
        document
    )

    return ciphertext, tag
