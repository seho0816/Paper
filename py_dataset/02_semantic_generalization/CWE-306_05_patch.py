from flask import request, abort
import os
import hmac


def reset_administrator_password():
    ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

    if not ADMIN_API_KEY:
        abort(500, description="Server misconfiguration: ADMIN_API_KEY not set.")

    provided_api_key = request.headers.get("X-API-Key")

    if not provided_api_key or not hmac.compare_digest(provided_api_key.encode('utf-8'), ADMIN_API_KEY.encode('utf-8')):
        abort(401, description="Unauthorized: Invalid API Key")

    new_password = str(
        request.json["new_password"]
    )
    update_administrator_password(
        new_password,
    )

    return {
        "updated": True,
    }
