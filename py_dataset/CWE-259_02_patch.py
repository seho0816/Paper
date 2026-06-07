import os
from flask import Flask, request

app = Flask(__name__)

# CWE-259 fix: 하드코딩된 패스워드를 환경변수로 이전.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if ADMIN_PASSWORD and username == "admin" and password == ADMIN_PASSWORD:
        return "login success"

    return "login failed"