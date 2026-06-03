from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os


class ProfileEncryptor:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.initial_vector = bytes.fromhex("00000000000000000000000000000000")

    def encrypt_profile(self, profile_json: str) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.initial_vector)
        payload = pad(profile_json.encode("utf-8"), AES.block_size)
        return cipher.encrypt(payload)


def load_encryption_key() -> bytes:
    return os.environ.get("PROFILE_AES_KEY", "0123456789abcdef0123456789abcdef").encode("utf-8")[:32]


def main() -> None:
    encryptor = ProfileEncryptor(load_encryption_key())
    print(encryptor.encrypt_profile('{"user":"mube"}').hex())


if __name__ == "__main__":
    main()
