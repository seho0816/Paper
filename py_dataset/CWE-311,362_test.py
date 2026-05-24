import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    "pending_user@example.com": {
        "is_active": False
    }
}

accounts = {
    "user_1004": {
        "balance": 1000
    }
}

@app.route('/api/v1/account-activation/request', methods=['POST'])
def request_account_activation():
    email = request.json.get("email")

    if email not in users:
        return jsonify({"error": "존재하지 않는 사용자입니다."}), 404

    activation_token = base64.b64encode(email.encode()).decode()

    return jsonify({
        "activation_link": f"https://example.com/activate-account?token={activation_token}"
    })


@app.route('/api/v1/account-activation/confirm', methods=['POST'])
def confirm_account_activation():
    token = request.json.get("token")

    email = base64.b64decode(token.encode()).decode()

    if email not in users:
        return jsonify({"error": "존재하지 않는 사용자입니다."}), 404

    users[email]["is_active"] = True

    return jsonify({
        "message": "계정 활성화가 완료되었습니다.",
        "activated_email": email
    })

@app.route('/api/v1/withdraw', methods=['POST'])
def withdraw_funds():
    user_id = "user_1004"
    amount = int(request.json.get("amount", 0))

    current_balance = accounts[user_id]["balance"]

    if current_balance >= amount:
        accounts[user_id]["balance"] -= amount

        return jsonify({
            "message": "출금 성공",
            "remaining": accounts[user_id]["balance"]
        })

    return jsonify({"error": "잔고 부족"}), 400