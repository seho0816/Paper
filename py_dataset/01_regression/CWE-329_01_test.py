from Crypto.Cipher import AES


def encrypt_record(
    key: bytes,
    padded_record: bytes,
) -> bytes:
    iv = key[:16]
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    return cipher.encrypt(
        padded_record
    )
