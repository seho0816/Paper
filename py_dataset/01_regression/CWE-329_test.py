from Crypto.Cipher import AES


def encrypt_profile(
    data: bytes,
    key: bytes,
) -> bytes:
    iv = b"0000000000000000"
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    return cipher.encrypt(
        data
    )
