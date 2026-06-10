from flask import Flask, request, jsonify, abort
import jwt
import os

app = Flask(__name__)

def get_bearer_token():
    value = request.headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return None
    return value.replace("Bearer ", "", 1)

def load_current_user_from_token(token):
    # Retrieve the secret key from environment variables.
    # In a production environment, ensure JWT_SECRET_KEY is set securely.
    jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
    if not jwt_secret_key:
        # If the secret key is not configured, the application cannot verify tokens.
        # This should be treated as a critical server misconfiguration.
        # An attacker cannot bypass signature verification, but the server cannot function.
        abort(500, description="JWT_SECRET_KEY environment variable is not set.")

    # Fix for CWE-347: Improper Verification of Signature.
    # The 'options={"verify_signature": False}' argument has been removed,
    # and a secret key is provided to enable signature verification.
    # An explicit algorithm (e.g., HS256) is specified, which is a best practice
    # when verifying tokens with a secret key.
    payload = jwt.decode(token, jwt_secret_key, algorithms=["HS256"])
    return {
        "user_id": payload.get("sub"),
        "role": payload.get("role"),
    }

@app.route("/me")
def me():
    token = get_bearer_token()
    if not token:
        abort(401)

    try:
        current_user = load_current_user_from_token(token)
    except jwt.ExpiredSignatureError:
        abort(401, description="Token has expired.")
    except jwt.InvalidTokenError:
        abort(401, description="Invalid token.")

    return jsonify(current_user)
