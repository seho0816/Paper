from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/send-login", methods=["POST"])
def send_login():
    username = request.form.get("username")
    password = request.form.get("password")

    response = requests.post(
        "http://example.com/api/login",
        data={
            "username": username,
            "password": password
        }
    )

    return response.text