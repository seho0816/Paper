import hashlib
import hmac

from Crypto.Cipher import AES


def decrypt_record(
    encryption_key: bytes,
    mac_key: bytes,
    iv: bytes,
    ciphertext: bytes,
    submitted_mac: bytes,
) -> bytes:
    expected_mac = hmac.new(
        mac_key,
        iv + ciphertext,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(
        expected_mac,
        submitted_mac,
    ):
        raise PermissionError(
            "invalid message authentication code"
        )

    cipher = AES.new(
        encryption_key,
        AES.MODE_CBC,
        iv=iv,
    )

    return cipher.decrypt(
        ciphertext
    )
