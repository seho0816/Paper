import hmac
import hashlib
import os
import base64

SECRET_KEY_ENV_VAR = "COOKIE_SIGNING_SECRET"

def load_my_profile(cookies: dict) -> dict:
    signed_user_id_cookie_value = cookies.get("user_id")

    if not signed_user_id_cookie_value:
        raise PermissionError("login required")

    secret_key = os.environ.get(SECRET_KEY_ENV_VAR)
    if not secret_key:
        raise RuntimeError(f"Missing environment variable: {SECRET_KEY_ENV_VAR}")
    secret_key_bytes = secret_key.encode('utf-8')

    if "." not in signed_user_id_cookie_value:
        raise PermissionError("invalid or malformed user_id cookie")

    user_id_b64_payload, signature = signed_user_id_cookie_value.split(".", 1)

    try:
        # Validate that the payload is valid base64 before proceeding to HMAC check
        base64.urlsafe_b64decode(user_id_b64_payload.encode('utf-8'))
    except base64.binascii.Error:
        raise PermissionError("invalid or malformed user_id cookie payload")

    expected_signature = hmac.new(
        secret_key_bytes,
        user_id_b64_payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        raise PermissionError("invalid or tampered user_id cookie")

    try:
        user_id = base64.urlsafe_b64decode(user_id_b64_payload.encode('utf-8')).decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError):
        raise PermissionError("failed to decode user_id from cookie")

    return account_repository.find(user_id)
