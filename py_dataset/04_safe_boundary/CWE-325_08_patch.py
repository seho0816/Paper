from Crypto.Cipher import AES


def decrypt_message(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
    )

    return cipher.decrypt_and_verify(
        ciphertext,
        tag,
    )

