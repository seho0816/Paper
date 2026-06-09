from flask import Flask, request
from cryptography.fernet import Fernet

app = Flask(__name__)

SECRET_KEY = b"yJbA9L2mV7qR4xT8nK3pQ6zC1sD5fG0hI9jE2wU3rY4="

@app.route("/encrypt")
def encrypt_value():
    value = request.args.get("value")

    cipher = Fernet(SECRET_KEY)
    encrypted = cipher.encrypt(value.encode("utf-8"))

    return encrypted.decode("utf-8")