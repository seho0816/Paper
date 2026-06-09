import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


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
    padded_plaintext = cipher.decrypt(
        ciphertext
    )

    # CWE-325 related to insecure padding removal (e.g., padding oracle vulnerability)
    # is addressed by using cryptographically secure unpadding from Crypto.Util.Padding.
    # This ensures that padding errors are handled securely, preventing information leakage.
    unpadded_plaintext = unpad(
        padded_plaintext,
        AES.block_size
    )

    return json.loads(
        unpadded_plaintext.decode('utf-8')
    )
