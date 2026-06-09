from flask import Flask, request

app = Flask(__name__)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234"

@app.route("/admin-login", methods=["POST"])
def admin_login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return "admin login success"

    return "login failed"