# 복합 CWE임
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {}

def create_user_record(username, password):
    return {
        "username": username,
        "password": password,
        "status": "active",
    }

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or password is None:
        return jsonify({"error": "missing field"}), 400

    users[username] = create_user_record(username, password)

    return jsonify({
        "message": "signup complete",
        "username": username,
    })
