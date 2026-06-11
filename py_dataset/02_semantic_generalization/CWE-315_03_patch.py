from flask import make_response
from cryptography.fernet import Fernet
import os


def send_reset_page(
    reset_token: str,
):
    fernet_key = os.environ["FLASK_FERNET_KEY"]
    f = Fernet(fernet_key)
    encrypted_token = f.encrypt(reset_token.encode('utf-8')).decode('utf-8')

    response = make_response(
        "reset page"
    )
    response.set_cookie(
        "reset_token",
        encrypted_token,
        httponly=True,
        secure=True,
    )

    return response
