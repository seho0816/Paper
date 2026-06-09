from flask import Flask, request, jsonify

app = Flask(__name__)

def get_user_from_token(token: str) -> dict | None:
    """
    실제 구현에서는 JWT 디코딩 또는 세션 DB 조회를 수행.
    여기서는 구조 시연용 스텁(stub) 함수.
    """
    # 예: return {"user_id": 1, "role": "admin"}
    return None

@app.route('/api/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({"error": "로그인이 필요합니다."}), 401

    # [PATCH CWE-285] 인가(Authorization) 검증 추가:
    # 토큰의 존재 여부(인증)만 확인하는 것으로는 부족함.
    # 반드시 해당 사용자가 'admin' 역할을 가졌는지 권한(Role)을 검사해야 함.
    current_user = get_user_from_token(auth_token)
    if current_user is None or current_user.get("role") != "admin":
        return jsonify({"error": "관리자 권한이 없습니다."}), 403

    return jsonify({"message": f"{user_id}번 사용자가 영구 삭제되었습니다."})

if __name__ == '__main__':
    app.run()