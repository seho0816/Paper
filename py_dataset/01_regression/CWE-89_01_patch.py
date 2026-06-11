import sqlite3

from flask import Flask, request

app = Flask(__name__)

connection = sqlite3.connect(
    "catalog.db",
)

# Define a whitelist of allowed columns for sorting
ALLOWED_SORT_COLUMNS = ["name", "price"]


@app.get("/api/products")
def list_products():
    sort_column = request.args.get(
        "sort",
        "name",
    )

    # Validate the sort_column against the whitelist to prevent SQL injection
    if sort_column not in ALLOWED_SORT_COLUMNS:
        sort_column = "name"  # Default to a safe column if an invalid one is provided

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
