import secrets
import string

from flask import Flask, jsonify

app = Flask(__name__)

TOKEN_ALPHABET = string.ascii_letters + string.digits


@app.post("/api/v1/partner-invitations")
def create_partner_invitation():
    invitation_code = "".join(
        secrets.choice(TOKEN_ALPHABET)
        for _ in range(28)
    )

    return jsonify({
        "invitation_code": invitation_code,
        "expires_in_seconds": 1800,
    })
