from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import padding

def decrypt_cookie_payload(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    # CWE-325: 본래는 MAC이 포함된 GCM이 좋으나, 기존 함수의 파라미터 구조(key, iv, ciphertext)를 보존
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    decryptor = cipher.decryptor()

    padded_plaintext = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext