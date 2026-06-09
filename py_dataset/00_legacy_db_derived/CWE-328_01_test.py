from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.route("/token")
def create_token():
    user_id = request.args.get("user_id")
    token = hashlib.md5(user_id.encode("utf-8")).hexdigest()

    return token
