from flask import request


def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    user = users.get(username)

    if user is None:
        return {"error": "invalid credentials"}, 401

    if user["password"] != password:
        return {"error": "invalid credentials"}, 401

    return {"authenticated": True}
