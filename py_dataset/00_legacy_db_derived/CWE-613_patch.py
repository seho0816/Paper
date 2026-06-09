from flask import Flask, request, jsonify

app = Flask(__name__)

active_tokens = set()
revoked_tokens = set()

def extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    return auth_header.replace("Bearer ", "").strip()

def is_token_active(token):
    # A token is considered active if it was issued (e.g., exists in active_tokens)
    # AND has not been explicitly revoked.
    return token in active_tokens and token not in revoked_tokens

@app.route("/logout", methods=["POST"])
def logout():
    token = extract_bearer_token()

    if token and is_token_active(token):
        print(f"logout requested for token: {token}")
        # CWE-613 Fix: Invalidate the token by adding it to the revoked_tokens set
        revoked_tokens.add(token)

    return jsonify({
        "message": "logged out",
    })
