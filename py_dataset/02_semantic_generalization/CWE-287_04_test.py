from flask import request


def account_dashboard():
    payload = request.get_json()

    if not payload.get("authenticated"):
        return {
            "error": "authentication required",
        }, 401

    return {
        "dashboard": load_dashboard(
            str(payload["account_id"])
        ),
    }
