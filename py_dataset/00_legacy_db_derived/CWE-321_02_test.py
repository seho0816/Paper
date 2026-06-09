from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

AES_KEY = b"0123456789abcdef0123456789abcdef"

aesgcm = AESGCM(AES_KEY)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, b"secret-data", None)
