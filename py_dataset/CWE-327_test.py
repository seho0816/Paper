from flask import Flask, request
from Crypto.Cipher import DES
import base64

app = Flask(__name__)

@app.route("/encrypt")
def encrypt_message():
    message = request.args.get("message", "")

    key = b"8bytekey"
    cipher = DES.new(key, DES.MODE_ECB)

    padded = message.ljust(8)
    encrypted = cipher.encrypt(padded.encode("utf-8"))

    return base64.b64encode(encrypted).decode("utf-8")