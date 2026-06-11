from flask import Flask, jsonify, request

app = Flask(__name__)

ALLOWED_ORIGINS = {
    "https://www.example.com",
    "http://localhost:3000",
}


@app.get("/api/account/statement")
def get_account_statement():
    request_origin = request.headers.get("Origin")
    response = jsonify({
        "account_id": "acct-2048",
        "current_balance": 420000,
    })

    if request_origin and request_origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = request_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response
