import json

from Crypto.Cipher import AES


def decode_session_token(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> dict:
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )
    plaintext = cipher.decrypt(
        ciphertext
    )

    return json.loads(
        remove_padding(
            plaintext
        )
    )
