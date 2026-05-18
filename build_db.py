import os
import chromadb

# 1. DB 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

print("=== CWE-311 'Missing Encryption' 지식 범위를 수정합니다 ===")

# 2. ChromaDB 클라이언트 연결
try:
    client = chromadb.PersistentClient(path=db_path)
except Exception as e:
    print(f"DB 초기화 실패: {e}")
    exit()

# 3. 컬렉션 불러오기
collection_name = "python_security_lessons"
collection = client.get_or_create_collection(name=collection_name)

# ==========================================
# 📚 [Snyk: Missing Encryption]
# - 기존 CWE-311 지식 범위 수정
# ==========================================

missing_encryption_doc = """
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

# 🚨 취약점: 암호화 누락 (CWE-311)
# 비밀번호 재설정 토큰을 암호화나 서명 없이 Base64 인코딩만으로 생성함
# Base64는 누구나 쉽게 복호화 및 위조할 수 있으므로, 보안 토큰으로 신뢰하면 안 됨
@app.route('/api/v1/password-reset/request', methods=['POST'])
def request_password_reset():
    email = request.json.get("email")

    # 사용자 이메일을 단순 Base64 인코딩하여 재설정 토큰으로 사용
    reset_token = base64.b64encode(email.encode()).decode()

    return jsonify({
        "reset_link": f"https://example.com/reset-password?token={reset_token}"
    })


@app.route('/api/v1/password-reset/confirm', methods=['POST'])
def confirm_password_reset():
    token = request.json.get("token")
    new_password = request.json.get("new_password")

    # 🚨 취약한 로직:
    # 토큰의 무결성 검증 없이 Base64 디코딩 결과를 그대로 신뢰함
    email = base64.b64decode(token.encode()).decode()

    # 공격자는 다른 사용자의 이메일을 Base64로 인코딩해 위조 토큰을 만들 수 있음
    update_user_password(email, new_password)

    return jsonify({"message": "비밀번호가 변경되었습니다."})
"""

missing_encryption_meta = {
    "cwe": "CWE-311",
    "full_text": """
[취약점 명칭] Missing Encryption (암호화 누락)
[CWE 번호] CWE-311 (민감한 데이터의 암호화 누락)

[상세 설명]
민감하거나 신뢰성이 필요한 데이터를 암호화 또는 무결성 보호 없이 처리할 경우, 공격자가 해당 값을 쉽게 해석하거나 위조하여 악용할 수 있는 취약점입니다.

본 지식은 CWE-311의 모든 암호화 누락 사례를 포괄적으로 다루는 것이 아니라, Snyk의 Missing Encryption 레슨에서 제시한 취약 원리를 기반으로, 비밀번호 재설정·이메일 인증·계정 활성화 등 보안상 신뢰되는 토큰을 Base64와 같은 가역적 인코딩만으로 생성하거나 보호하고, 서버가 해당 값을 해석한 뒤 별도의 서명 또는 무결성 검증 없이 신뢰하는 Python 코드 패턴을 중심으로 저장합니다.

Base64는 데이터를 문자 형태로 변환하는 인코딩 방식일 뿐, 암호화나 전자서명 기능을 제공하지 않습니다. 그럼에도 비밀번호 재설정 토큰, 이메일 인증 토큰, 계정 활성화 토큰 등 보안상 중요한 값을 Base64만으로 생성하고, 서버가 이를 복호화한 뒤 검증 없이 신뢰하면 문제가 발생합니다.

예를 들어 서버가 `base64(email)` 형태의 재설정 토큰을 발급하고, 이후 이를 디코딩한 이메일 주소를 기준으로 비밀번호 변경을 허용한다면, 공격자는 임의의 이메일 주소를 직접 Base64로 인코딩하여 다른 사용자의 토큰을 위조할 수 있습니다. 같은 원리는 이메일 인증이나 계정 활성화 흐름에서도 발생할 수 있으며, 공격자는 위조된 토큰을 통해 의도하지 않은 계정 검증이나 상태 변경을 유발할 수 있습니다.

[해결책 및 개선 코드]
보안 토큰은 단순 인코딩이 아니라, 공격자가 임의로 조작할 수 없도록 무결성이 보장되어야 합니다. 이를 위해 서버 비밀키로 서명된 토큰을 사용하거나, 충분히 예측하기 어려운 난수 토큰을 생성해 서버 측 저장소(DB, Redis 등)에 보관한 뒤 검증하는 방식이 필요합니다.

파이썬에서는 JWT와 같은 서명 기반 토큰을 사용할 수 있으며, 토큰을 검증할 때는 반드시 서명, 만료 시간, 토큰 목적 등을 함께 확인해야 합니다.

**[안전한 코드 예시 (서명된 JWT 토큰 사용)]**
```python
import jwt
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_KEY = "server-side-secret-key"

def create_reset_token(email: str) -> str:
    payload = {
        "email": email,
        "purpose": "password_reset",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


@app.route('/api/v1/password-reset/request-secure', methods=['POST'])
def request_password_reset_secure():
    email = request.json.get("email")

    # 💡 안전한 로직: 서버 비밀키로 서명된 토큰 발급
    reset_token = create_reset_token(email)

    return jsonify({
        "reset_link": f"https://example.com/reset-password?token={reset_token}"
    })


@app.route('/api/v1/password-reset/confirm-secure', methods=['POST'])
def confirm_password_reset_secure():
    token = request.json.get("token")
    new_password = request.json.get("new_password")

    try:
        # 💡 안전한 로직: 토큰 서명과 만료 여부를 함께 검증
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        if payload.get("purpose") != "password_reset":
            return jsonify({"error": "잘못된 토큰 목적"}), 400

        email = payload.get("email")
        update_user_password(email, new_password)

        return jsonify({"message": "비밀번호가 변경되었습니다."})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "만료된 토큰입니다."}), 400

    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 400
        """
}
try:
    collection.upsert(
    documents=[missing_encryption_doc],
    metadatas=[missing_encryption_meta],
    ids=["snyk_lesson_missing_encryption_base64_token"]
    )

    print("\n✅ 'CWE-311 Missing Encryption' 지식 범위가 성공적으로 수정되었습니다!")
    print("   → 비밀번호 재설정 토큰 중심에서")
    print("   → 보안상 신뢰되는 Base64 기반 토큰 위조 패턴으로 범위를 확장했습니다.")
    print(f"현재 DB 총 지식 수: {collection.count()}개")
except Exception as e:
    print(f"\n⚠️ 데이터 수정 중 오류가 발생했습니다: {e}")