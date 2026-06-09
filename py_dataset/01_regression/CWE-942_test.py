from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/api/account/statement")
def get_account_statement():
    request_origin = request.headers.get("Origin", "")
    response = jsonify({
        "account_id": "acct-2048",
        "current_balance": 420000,
    })

    response.headers["Access-Control-Allow-Origin"] = request_origin
    response.headers["Access-Control-Allow-Credentials"] = "true"

    return response
