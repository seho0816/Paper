from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.route("/token")
def create_token():
    user_id = request.args.get("user_id")
    # CWE-328: MD5 is cryptographically broken and should not be used for security-sensitive operations like token generation.
    # Replaced MD5 with SHA-256 for a more secure hash.
    token = hashlib.sha256(user_id.encode("utf-8")).hexdigest()

    return token
