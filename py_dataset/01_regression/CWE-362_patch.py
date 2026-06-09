import threading
from flask import Flask, jsonify, request

app = Flask(__name__)

wallets = {
    "member-100": {
        "balance": 100000,
    },
}

# Add a lock to protect concurrent access to wallet balances
wallet_lock = threading.Lock()


@app.post("/api/wallet/withdraw")
def withdraw():
    amount = int(request.json["amount"])
    
    # Acquire the lock before accessing and modifying the shared wallet resource
    with wallet_lock:
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
