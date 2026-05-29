from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/orders/<order_id>")
def get_order(order_id):
    current_user_id = request.headers.get("X-User-Id")

    if current_user_id is None:
        return "login required", 401

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, user_id, product_name, total_price FROM orders WHERE id = ?",
        (order_id,)
    )

    row = cursor.fetchone()
    conn.close()

    return jsonify({
        "order_id": row[0],
        "user_id": row[1],
        "product_name": row[2],
        "total_price": row[3]
    })