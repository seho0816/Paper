from flask import Flask, jsonify, request

app = Flask(__name__)

TRUSTED_ORIGINS = {
    "https://account.example.com",
    "https://support.example.com",
}


@app.get("/api/account/preferences")
def get_account_preferences():
    origin = request.headers.get("Origin", "")
    response = jsonify({
        "language": "ko",
        "timezone": "Asia/Seoul",
    })

    if origin in TRUSTED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"

    return response
