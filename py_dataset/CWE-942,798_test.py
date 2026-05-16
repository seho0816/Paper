from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2

app = Flask(__name__)

CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=True
)

DB_PASSWORD = "SuperSecretDbPassword2026!@"

@app.route('/api/admin/report', methods=['GET'])
def get_admin_report():
    connection = psycopg2.connect(
        host="prod-db.internal.company.com",
        database="finance_data",
        user="admin_svc_account",
        password=DB_PASSWORD
    )

    cursor = connection.cursor()
    cursor.execute("SELECT report_name, total_amount FROM monthly_reports LIMIT 10;")
    rows = cursor.fetchall()

    cursor.close()
    connection.close()

    return jsonify({
        "status": "success",
        "reports": rows
    })

if __name__ == '__main__':
    app.run()