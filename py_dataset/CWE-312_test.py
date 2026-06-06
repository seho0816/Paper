from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password) VALUES (?, ?)",
        (username, password)
    )

    conn.commit()
    conn.close()

    return "registered"