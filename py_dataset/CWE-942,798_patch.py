from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
import os

app = Flask(__name__)

# [PATCH CWE-942] 와일드카드 CORS + credentials 조합 금지:
# origins='*'와 supports_credentials=True를 함께 사용하면
# 모든 출처의 요청이 인증 정보(쿠키, 세션)를 포함하여 API에 접근할 수 있음.
# 신뢰할 수 있는 출처만 명시적으로 허용해야 함.
ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "https://your-trusted-frontend.com").split(",")

CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True
)

@app.route('/api/admin/report', methods=['GET'])
def get_admin_report():
    # [PATCH CWE-798] 하드코딩된 DB 비밀번호를 환경 변수로 이동
    connection = psycopg2.connect(
        host=os.environ.get("DB_HOST", "prod-db.internal.company.com"),
        database=os.environ.get("DB_NAME", "finance_data"),
        user=os.environ.get("DB_USER", "admin_svc_account"),
        password=os.environ.get("DB_PASSWORD")  # 환경 변수에서만 읽음, 기본값 없음
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