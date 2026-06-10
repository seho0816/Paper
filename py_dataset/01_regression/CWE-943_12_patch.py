from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient("mongodb://localhost:27017")
users = client["app"]["users"]

def normalize_login_payload(payload):
    if payload is None:
        return {}
    return payload

@app.route("/login", methods=["POST"])
def login():
    payload = normalize_login_payload(request.json)

    username = payload.get("username")
    password = payload.get("password")

    query = {}
    if isinstance(username, str) and username:
        query["username"] = username
    if isinstance(password, str) and password:
        query["password"] = password

    if not query or "username" not in query or "password" not in query:
        return jsonify({"message": "login failed"}), 401

    user = users.find_one(query)

    if user:
        return jsonify({
            "message": "login success",
            "user_id": str(user.get("_id")),
        })

    return jsonify({"message": "login failed"}), 401
