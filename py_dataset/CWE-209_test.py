from flask import Flask, request
import sqlite3
import traceback

app = Flask(__name__)

@app.route("/search")
def search():
    keyword = request.args.get("keyword")

    try:
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()

        query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
        cursor.execute(query)

        return str(cursor.fetchall())

    except Exception:
        return traceback.format_exc()