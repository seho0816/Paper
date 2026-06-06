from flask import Flask, request, jsonify

app = Flask(__name__)

active_tokens = set()
revoked_tokens = set()

def extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    return auth_header.replace("Bearer ", "").strip()

def is_token_active(token):
    return token in active_tokens

@app.route("/logout", methods=["POST"])
def logout():
    token = extract_bearer_token()

    if token and is_token_active(token):
        print(f"logout requested for token: {token}")

    return jsonify({
        "message": "logged out",
    })
