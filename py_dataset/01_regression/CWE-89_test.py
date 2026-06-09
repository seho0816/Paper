import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/api/users")
def read_user():
    user_id = request.args.get(
        "id",
        "",
    )
    connection = sqlite3.connect(
        "app.db",
    )
    cursor = connection.cursor()
    query = (
        "SELECT id, email FROM users "
        f"WHERE id = '{user_id}'"
    )

    cursor.execute(query)
    return {
        "rows": cursor.fetchall(),
    }
