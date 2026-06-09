from flask import request
import sqlite3

def list_products():
    # Define a whitelist of allowed sort columns to prevent SQL injection in the ORDER BY clause.
    allowed_sort_columns = ["name", "price"]

    sort = request.args.get("sort", "name")

    # Validate the 'sort' parameter against the whitelist.
    # If the provided sort value is not in the whitelist, default to a safe column.
    if sort not in allowed_sort_columns:
        sort = "name" # Default to 'name' if an invalid sort column is requested

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # The 'sort' parameter is now guaranteed to be one of the whitelisted column names,
    # making the query safe from SQL injection.
    query = f"SELECT name, price FROM products ORDER BY {sort}"
    cursor.execute(query)

    return cursor.fetchall()
