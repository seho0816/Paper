from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

AES_KEY = os.urandom(32)

aesgcm = AESGCM(AES_KEY)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, b"secret-data", None)
