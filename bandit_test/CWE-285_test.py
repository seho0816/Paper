from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({"error": "로그인이 필요합니다."}), 401
    
    return jsonify({"message": f"{user_id}번 사용자가 영구 삭제되었습니다."})

if __name__ == '__main__':
    app.run()