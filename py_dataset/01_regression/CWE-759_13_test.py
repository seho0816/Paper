from flask import Flask, request
import hashlib
import sqlite3

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()

    return "signup complete"