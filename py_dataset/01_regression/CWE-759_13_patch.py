from flask import Flask, request
import sqlite3
import bcrypt # Import bcrypt for strong password hashing

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    # CWE-759 fix: Use a strong, salted, key-stretching password hashing algorithm (bcrypt)
    # bcrypt.gensalt() generates a new salt for each hash
    # bcrypt.hashpw returns bytes, so decode to utf-8 for storage in the database
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()

    return "signup complete"
