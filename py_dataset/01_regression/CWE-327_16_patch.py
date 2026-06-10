from flask import Flask, request
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

@app.route("/encrypt")
def encrypt_message():
    message = request.args.get("message", "")

    key = b"Sixteen byte key"
    cipher = AES.new(key, AES.MODE_GCM)

    plaintext_bytes = message.encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

    return base64.b64encode(cipher.nonce + ciphertext + tag).decode("utf-8")
