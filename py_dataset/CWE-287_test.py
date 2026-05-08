from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # (비밀번호 검증 로직 생략)
    
    response = jsonify({"message": "로그인 성공"})
    
    response.set_cookie('user_role', 'guest') 
    return response

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    
    role = request.cookies.get('user_role')
    
    if role == 'admin':
        return jsonify({"status": "success", "data": "서버의 핵심 설정 정보 (관리자 전용)"})
    else:
        return jsonify({"error": "접근 권한이 없습니다."}), 401

if __name__ == '__main__':
    app.run()