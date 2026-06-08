import re
import bcrypt
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {}

# CWE-521 Fix: Enforce password strength requirements
# Minimum 8 characters, at least one uppercase, one lowercase, one digit, one special char
_PASSWORD_MIN_LEN = 8
_PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{8,}$'
)

def is_strong_password(password: str) -> bool:
    """CWE-521: Validate password meets minimum strength requirements."""
    if len(password) < _PASSWORD_MIN_LEN:
        return False
    return bool(_PASSWORD_PATTERN.match(password))

def create_user_record(username, password):
    # CWE-256/257 Fix: Hash password with bcrypt before storing
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return {
        "username": username,
        "password": hashed.decode('utf-8'),
        "status": "active",
    }

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or password is None:
        return jsonify({"error": "missing field"}), 400

    # CWE-521 Fix: Reject weak passwords before storing
    if not is_strong_password(password):
        return jsonify({
            "error": "password too weak",
            "requirements": (
                "minimum 8 characters, at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
        }), 400

    users[username] = create_user_record(username, password)

    return jsonify({
        "message": "signup complete",
        "username": username,
    })