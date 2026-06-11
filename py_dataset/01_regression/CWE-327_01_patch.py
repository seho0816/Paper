import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto import Random


def encrypt_record(record: bytes) -> bytes:
    key = os.environ["AES_KEY"].encode("utf-8")
    
    # Generate a unique and random Initialization Vector (IV) for CBC mode.
    # The IV must be the same size as the AES block size (typically 16 bytes).
    # It does not need to be secret but must be unique for each encryption.
    iv = Random.get_random_bytes(AES.block_size)
    
    # Use AES.MODE_CBC (Cipher Block Chaining) instead of the insecure AES.MODE_ECB.
    # CBC mode uses an IV to randomize the encryption of identical plaintext blocks,
    # preventing patterns from appearing in the ciphertext.
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    ciphertext = cipher.encrypt(
        pad(record, AES.block_size)
    )
    
    # Prepend the IV to the ciphertext. The IV is necessary for decryption
    # and is conventionally transmitted alongside the ciphertext.
    return iv + ciphertext
