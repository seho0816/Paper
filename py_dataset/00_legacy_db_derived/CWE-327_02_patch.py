from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = os.environ["AES_KEY"].encode("utf-8")

# Generate a unique nonce for AES GCM mode.
# NIST SP 800-38D recommends a 96-bit (12-byte) nonce for GCM,
# but PyCryptodome's AES.new(mode=AES.MODE_GCM) can use 16 bytes by default or a specified nonce_size.
# Using 16 bytes here as it's a common and acceptable practice with PyCryptodome.
nonce = os.urandom(16)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

plaintext = b"secret message"
# Although GCM does not strictly require padding, the original code uses pad.
# To maintain the existing functional structure as per strict rules, padding is kept.
padded_plaintext = pad(plaintext, AES.block_size)

# Encrypt the padded plaintext and generate the authentication tag.
ciphertext, tag = cipher.encrypt_and_digest(padded_plaintext)

# For decryption and authentication, the nonce, ciphertext, and tag are all required.
# They are concatenated here to form the complete 'encrypted' data block.
encrypted = nonce + ciphertext + tag
