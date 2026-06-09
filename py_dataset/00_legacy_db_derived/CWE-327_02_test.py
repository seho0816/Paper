from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = os.environ["AES_KEY"].encode("utf-8")
cipher = AES.new(key, AES.MODE_ECB)

plaintext = b"secret message"
encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
