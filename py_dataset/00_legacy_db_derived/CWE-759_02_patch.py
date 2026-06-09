from flask import Flask, request
import bcrypt

app = Flask(__name__)

def save_password_hash(password_hash):
    return True

@app.route("/signup", methods=["POST"])
def signup():
    password = request.form.get("password")

    # CWE-759 fix: Replaced insecure MD5 hashing with bcrypt, a strong password hashing algorithm.
    # bcrypt automatically generates a salt and incorporates it into the hash, addressing CWE-759.
    # It also provides key stretching to make brute-force attacks more difficult.
    # The password must be encoded to bytes before hashing.
    # The resulting hash (bytes) is then decoded to a UTF-8 string for storage.
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    save_password_hash(password_hash)

    return "signup complete"
