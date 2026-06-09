from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os


class ProfileEncryptor:
    def __init__(self, key: bytes) -> None:
        self.key = key
        # CWE-329 Fix: The initial_vector should be randomly generated for each encryption
        # when using CBC mode to prevent reuse of IVs, which can lead to attacks.
        # Although 'self.initial_vector' is declared here in the original structure,
        # its fixed value is the vulnerability. We will generate a new random IV
        # inside the 'encrypt_profile' method, effectively ignoring this fixed value
        # for actual encryption operations, to adhere strictly to structure.
        self.initial_vector = bytes.fromhex("00000000000000000000000000000000")

    def encrypt_profile(self, profile_json: str) -> bytes:
        # CWE-329 Fix: Generate a new, random initialization vector (IV) for each encryption.
        # This ensures that the same plaintext does not produce the same ciphertext
        # and prevents statistical analysis attacks.
        iv = os.urandom(AES.block_size)  # AES.block_size is typically 16 bytes for AES

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        payload = pad(profile_json.encode("utf-8"), AES.block_size)
        ciphertext = cipher.encrypt(payload)
        
        # CWE-329 Fix: For decryption, the IV must be known. The standard practice
        # when using a randomly generated IV per message is to prepend it to the ciphertext.
        # The function signature (-> bytes) allows for this, as the return value is still bytes.
        return iv + ciphertext


def load_encryption_key() -> bytes:
    return os.environ.get("PROFILE_AES_KEY", "0123456789abcdef0123456789abcdef").encode("utf-8")[:32]


def main() -> None:
    encryptor = ProfileEncryptor(load_encryption_key())
    # Note: For decryption, the first AES.block_size (16) bytes of the returned hex string
    # would be the IV, and the rest would be the actual ciphertext.
    print(encryptor.encrypt_profile('{"user":"mube"}').hex())


if __name__ == "__main__":
    main()
