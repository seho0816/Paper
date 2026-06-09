from Crypto.Cipher import ARC4
import os

key = os.environ["ARC4_KEY"].encode("utf-8")
cipher = ARC4.new(key)
encrypted = cipher.encrypt(b"secret-data")
