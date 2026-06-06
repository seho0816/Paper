from flask import Flask, request, jsonify, abort
import jwt

app = Flask(__name__)

def get_bearer_token():
    value = request.headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return None
    return value.replace("Bearer ", "", 1)

def load_current_user_from_token(token):
    payload = jwt.decode(token, options={"verify_signature": False})
    return {
        "user_id": payload.get("sub"),
        "role": payload.get("role"),
    }

@app.route("/me")
def me():
    token = get_bearer_token()
    if not token:
        abort(401)

    current_user = load_current_user_from_token(token)

    return jsonify(current_user)
