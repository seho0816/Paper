import sqlite3

from flask import Flask, request

app = Flask(__name__)

connection = sqlite3.connect(
    "catalog.db",
)


@app.get("/api/products")
def list_products():
    sort_column = request.args.get(
        "sort",
        "name",
    )
    query = (
        "SELECT name, price "
        "FROM products "
        f"ORDER BY {sort_column}"
    )

    return {
        "rows": connection.execute(
            query,
        ).fetchall(),
    }
