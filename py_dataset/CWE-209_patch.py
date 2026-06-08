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

        # CWE-89 (SQL Injection) fix: Use parameterized queries to prevent SQL injection.
        # The '?' placeholder is used, and the parameter is passed as a tuple.
        cursor.execute("SELECT * FROM products WHERE name LIKE ?", ('%' + keyword + '%',))

        results = cursor.fetchall()
        conn.close() # It's good practice to close the database connection.

        return str(results)

    except Exception:
        # CWE-209 (Information Disclosure in Error Message) fix:
        # Instead of returning the full traceback, which can expose sensitive system information,
        # return a generic, non-informative error message to the user.
        # The actual exception details (from traceback.format_exc()) should be logged internally
        # for debugging purposes, but not exposed to the client.
        # (Assuming internal logging mechanism is in place, or print for demonstration)
        # For a real application, you'd use a proper logging library (e.g., import logging).
        # Keeping 'import traceback' for consistency with original structure,
        # it can be used for internal logging.
        print(f"An error occurred during search: {traceback.format_exc()}")
        return "An unexpected error occurred. Please try again later."
