from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # CWE-200 fix: Restrict the selected columns to only non-sensitive information.
    # 'email', 'phone', 'address' are considered sensitive and are removed.
    cursor.execute(
        "SELECT id, username FROM users WHERE id = ?",
        (user_id,)
    )

    row = cursor.fetchone()
    conn.close()

    # CWE-200 fix: Only return non-sensitive information in the JSON response.
    # The original code would raise an error if `row` is None (user not found),
    # and this behavior is preserved as per strict rule #2 and #4.
    return jsonify({
        "id": row[0],
        "username": row[1]
    })
