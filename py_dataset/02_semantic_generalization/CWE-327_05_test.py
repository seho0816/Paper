import os
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad


def encrypt_legacy_note(
    note: bytes,
) -> bytes:
    key = os.environ["BLOWFISH_KEY"].encode("utf-8")
    cipher = Blowfish.new(
        key,
        Blowfish.MODE_ECB,
    )

    return cipher.encrypt(
        pad(
            note,
            Blowfish.block_size,
        )
    )
