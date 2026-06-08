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

    # CWE-863 Fix: Ensure that the requested order belongs to the current_user_id
    # by including user_id in the WHERE clause of the SQL query.
    cursor.execute(
        "SELECT id, user_id, product_name, total_price FROM orders WHERE id = ? AND user_id = ?",
        (order_id, current_user_id)
    )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        # If no order is found for the given ID and user, return a 404 Not Found.
        # This prevents revealing whether the order exists but belongs to another user.
        return "Order not found or you are not authorized to view it", 404

    return jsonify({
        "order_id": row[0],
        "user_id": row[1],
        "product_name": row[2],
        "total_price": row[3]
    })
