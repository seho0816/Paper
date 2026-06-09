import os
from flask import Flask, request

app = Flask(__name__)

# CWE-259 fix: 하드코딩된 자격증명을 환경변수로 완전히 이전.
# 기본값을 두지 않아 환경변수 미설정 시 서버 시작 자체를 막음.
ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

@app.route("/admin-login", methods=["POST"])
def admin_login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return "admin login success"

    return "login failed"