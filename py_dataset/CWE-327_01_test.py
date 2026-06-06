from Crypto.Cipher import DES
import os

key = os.environ["DES_KEY"].encode("utf-8")
cipher = DES.new(key, DES.MODE_ECB)
encrypted = cipher.encrypt(b"message1")
