from flask import Flask, jsonify, request

app = Flask(__name__)

accounts = {
    "account-100": {
        "display_name": "member",
        "email": "member@example.com",
        "is_admin": False,
        "credit": 1000,
    },
}


@app.put("/api/accounts/<account_id>")
def update_account(account_id: str):
    account = accounts[account_id]
    update_data = request.get_json()

    # CWE-915 fix: Only allow modification of explicitly whitelisted attributes
    # This prevents malicious users from updating sensitive fields like 'is_admin'.
    allowed_fields = ["display_name", "email", "credit"]

    if update_data:
        for key, value in update_data.items():
            if key in allowed_fields:
                account[key] = value

    return jsonify(account)
