from Crypto.Cipher import AES
from Crypto.Util import Random
import os

key = os.environ["ARC4_KEY"].encode("utf-8")
nonce = Random.new().read(12) # GCM recommends a 12-byte nonce for security and performance

# Replace ARC4 with AES in GCM mode, which provides both confidentiality and authentication.
# The key length must be 16, 24, or 32 bytes for AES. It is assumed that 'key'
# obtained from the environment variable meets this requirement.
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

# Encrypt the data and generate an authentication tag.
# For decryption, the nonce, ciphertext, and tag are all required.
# Concatenate them for storage in a single 'encrypted' bytes object.
ciphertext, tag = cipher.encrypt_and_digest(b"secret-data")
encrypted = nonce + ciphertext + tag
