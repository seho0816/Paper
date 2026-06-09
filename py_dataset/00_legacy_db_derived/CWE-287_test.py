@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')

    response = jsonify({"message": "로그인 성공"})
    response.set_cookie('logged_in', 'true')
    response.set_cookie('username', username)
    return response

@app.route('/profile')
def profile():
    if request.cookies.get('logged_in') == 'true':
        return jsonify({"message": "인증된 사용자입니다."})
    return jsonify({"error": "로그인이 필요합니다."}), 401