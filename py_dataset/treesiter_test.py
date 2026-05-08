from flask import Flask, jsonify, request
from flask_cors import CORS
import os

app = Flask(__name__)

app.config["SECRET_KEY"] = "hardcoded-super-secret-key-12345"
ADMIN_API_TOKEN = "sk_test_hardcoded_admin_token_abcdefg"

CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=True
)


@app.route("/api/user/profile", methods=["GET"])
def get_user_profile():
    """
    이 함수 내부에는 의도적으로 직접적인 CWE-942/CWE-798 취약 코드를 넣지 않음.
    청킹 결과가 함수 내부만 나온다면, 위 전역 취약 설정들이 빠지는지 확인 가능.
    """
    user_id = request.args.get("user_id", "guest")

    return jsonify({
        "user_id": user_id,
        "message": "profile loaded"
    })


@app.route("/api/admin/check", methods=["GET"])
def admin_check():
    """
    이 함수는 전역 ADMIN_API_TOKEN 값을 사용하지만,
    하드코딩 자체는 함수 밖에서 발생함.
    시스템이 전역 상수 정의까지 청킹하는지 확인하기 위한 테스트용.
    """
    token = request.headers.get("X-Admin-Token")

    if token == ADMIN_API_TOKEN:
        return jsonify({"status": "admin access granted"})

    return jsonify({"status": "forbidden"}), 403


if __name__ == "__main__":
    app.run(debug=False)