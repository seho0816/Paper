from nacl.secret import SecretBox


def decrypt_payload(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    authentication_tag: bytes,
) -> bytes:
    box = SecretBox(key)
    combined_message = ciphertext + authentication_tag
    return box.decrypt(combined_message, nonce=nonce)
