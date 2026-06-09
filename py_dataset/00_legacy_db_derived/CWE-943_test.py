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

    user = users.find_one(payload)

    if user:
        return jsonify({
            "message": "login success",
            "user_id": str(user.get("_id")),
        })

    return jsonify({"message": "login failed"}), 401
