from flask import Flask, request
import hashlib

app = Flask(__name__)

def save_password_hash(password_hash):
    return True

@app.route("/signup", methods=["POST"])
def signup():
    password = request.form.get("password")

    password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    save_password_hash(password_hash)

    return "signup complete"
