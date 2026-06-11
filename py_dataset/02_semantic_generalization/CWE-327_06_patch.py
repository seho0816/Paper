import os
from Crypto.Cipher import AES


def encrypt_token(
    token: bytes,
    iv: bytes,
) -> bytes:
    key = os.environ["TOKEN_AES_KEY"].encode("utf-8")
    # CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    # AES.MODE_CBC provides confidentiality but no integrity or authenticity.
    # It is susceptible to padding oracle attacks or chosen-ciphertext attacks
    # if integrity is not handled separately.
    # AES.MODE_GCM provides authenticated encryption, ensuring both confidentiality
    # and integrity/authenticity, which is crucial for tokens.
    # The 'iv' parameter is used as the 'nonce' for GCM. While GCM typically uses
    # a 12-byte nonce, PyCryptodome's GCM implementation supports nonces of various
    # lengths, including the 16-byte block size typically used for CBC IVs.
    # The authentication tag is appended to the ciphertext to be returned,
    # as GCM requires both the ciphertext and tag for verification during decryption.
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=iv,
    )

    # For GCM mode, padding is not required as it handles arbitrary length plaintext.
    # encrypt_and_digest returns the ciphertext and the authentication tag.
    ciphertext, tag = cipher.encrypt_and_digest(token)

    # Return the ciphertext concatenated with the authentication tag.
    # The caller must ensure the 'iv' (nonce) is also available for decryption.
    return ciphertext + tag
