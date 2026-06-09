from Crypto.Cipher import AES
import os

# Assuming 'DES_KEY' now contains a key suitable for AES (e.g., 16, 24, or 32 bytes)
key = os.environ["DES_KEY"].encode("utf-8")

# Replaced DES with AES, and MODE_ECB with MODE_GCM for stronger security.
# MODE_GCM provides authenticated encryption, preventing tampering.
cipher = AES.new(key, AES.MODE_GCM)

# Encrypt the message. In GCM mode, this produces the ciphertext.
encrypted = cipher.encrypt(b"message1")

# For secure GCM, the nonce (Number used once) and the authentication tag
# are essential for decryption and integrity verification.
# These must be stored or transmitted along with the ciphertext.
nonce = cipher.nonce
tag = cipher.digest()
