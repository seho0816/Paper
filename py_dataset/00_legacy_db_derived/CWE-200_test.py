from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, email, phone, address FROM users WHERE id = ?",
        (user_id,)
    )

    row = cursor.fetchone()
    conn.close()

    return jsonify({
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "phone": row[3],
        "address": row[4]
    })