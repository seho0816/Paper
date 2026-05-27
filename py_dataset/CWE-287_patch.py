from flask import Flask, request, jsonify, session
import os
import secrets

app = Flask(__name__)
# [PATCH CWE-287] 서버 측 세션을 사용하려면 SECRET_KEY가 반드시 필요.
# 환경 변수에서 읽어오며, 없을 경우 안전한 랜덤 값 사용.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# 임시 사용자 DB (실제 구현에서는 DB 조회로 대체)
USERS = {"testuser": "correct_password"}

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # [PATCH CWE-287] 클라이언트가 조작 가능한 쿠키('logged_in=true')로 인증하는 것이 취약점.
    # 서버 측 세션(session)에 사용자 정보를 저장하여 클라이언트가 위변조할 수 없도록 함.
    if username in USERS and USERS[username] == password:
        session['username'] = username
        session['authenticated'] = True
        return jsonify({"message": "로그인 성공"})

    return jsonify({"error": "아이디 또는 비밀번호가 틀렸습니다."}), 401

@app.route('/profile')
def profile():
    # 세션은 서버가 서명하므로 클라이언트가 임의로 'authenticated=true'로 바꿀 수 없음
    if session.get('authenticated'):
        return jsonify({"message": f"인증된 사용자입니다: {session.get('username')}"})
    return jsonify({"error": "로그인이 필요합니다."}), 401