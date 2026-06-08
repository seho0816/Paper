import base64
import secrets
import threading
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

# CWE-362: Initialize locks for accounts to prevent race conditions
account_locks = {user_id: threading.Lock() for user_id in accounts}

@app.route('/api/v1/account-activation/request', methods=['POST'])
def request_account_activation():
    email = request.json.get("email")

    if email not in users:
        return jsonify({"error": "존재하지 않는 사용자입니다."}), 404

    # CWE-311: Use a cryptographically secure random token instead of base64 encoding the email
    # Base64 is encoding, not encryption, and easily reversible.
    activation_token = secrets.token_urlsafe(32)
    users[email]["activation_token"] = activation_token # Store the token for verification

    return jsonify({
        "activation_link": f"https://example.com/activate-account?token={activation_token}"
    })


@app.route('/api/v1/account-activation/confirm', methods=['POST'])
def confirm_account_activation():
    token = request.json.get("token")

    # CWE-311: Validate the token by looking it up, not by decoding the email from it
    email = None
    for user_email, user_data in users.items():
        if user_data.get("activation_token") == token:
            email = user_email
            break

    if email is None:
        return jsonify({"error": "유효하지 않거나 만료된 토큰입니다."}), 400

    users[email]["is_active"] = True
    # Optionally, invalidate the token after use to prevent replay
    # users[email]["activation_token"] = None

    return jsonify({
        "message": "계정 활성화가 완료되었습니다.",
        "activated_email": email
    })

@app.route('/api/v1/withdraw', methods=['POST'])
def withdraw_funds():
    user_id = "user_1004"
    amount = int(request.json.get("amount", 0))

    # CWE-362: Use a lock to prevent race conditions during read-modify-write operations on balance
    # This ensures that only one request can modify the balance for a given user at a time.
    if user_id not in account_locks:
        # For dynamically created accounts, initialize a new lock
        account_locks[user_id] = threading.Lock()
    
    lock = account_locks[user_id]

    with lock:
        current_balance = accounts[user_id]["balance"]

        if current_balance >= amount:
            accounts[user_id]["balance"] -= amount

            return jsonify({
                "message": "출금 성공",
                "remaining": accounts[user_id]["balance"]
            })

        return jsonify({"error": "잔고 부족"}), 400
