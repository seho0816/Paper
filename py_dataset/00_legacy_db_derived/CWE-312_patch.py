from flask import Flask, request
import sqlite3
from werkzeug.security import generate_password_hash

app = Flask(__name__)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password) VALUES (?, ?)",
        (username, hashed_password)
    )

    conn.commit()
    conn.close()

    return "registered"
