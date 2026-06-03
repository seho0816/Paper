from flask import request
import sqlite3

def list_products():
    sort = request.args.get("sort", "name")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    query = f"SELECT name, price FROM products ORDER BY {sort}"
    cursor.execute(query)

    return cursor.fetchall()
