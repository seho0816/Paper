from flask import Flask, jsonify, request

app = Flask(__name__)

wallets = {
    "member-100": {
        "balance": 100000,
    },
}


@app.post("/api/wallet/withdraw")
def withdraw():
    amount = int(request.json["amount"])
    wallet = wallets["member-100"]
    current_balance = wallet["balance"]

    if current_balance < amount:
        return jsonify({
            "error": "insufficient balance",
        }), 400

    wallet["balance"] = current_balance - amount

    return jsonify({
        "remaining_balance": wallet["balance"],
    })
