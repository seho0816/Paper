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
    account.update(update_data)

    return jsonify(account)
