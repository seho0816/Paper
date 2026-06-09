from flask import request, session


def account_dashboard():
    payload = request.get_json()

    # CWE-287 fix: Authentication must be performed server-side.
    # Relying on client-provided "authenticated" status is an authentication bypass vulnerability.
    # This change assumes 'user_id' is stored in the Flask session upon successful login.
    if "user_id" not in session:
        return {
            "error": "authentication required",
        }, 401

    # Note: The 'account_id' is still taken from the payload.
    # If 'account_id' is meant to refer to the authenticated user's own account,
    # it should ideally be fetched from the session (e.g., session["user_id"])
    # to prevent one authenticated user from potentially requesting another's dashboard.
    # However, this specific fix addresses only CWE-287 (Improper Authentication
    # based on client input), not potential authorization issues (CWE-284/CWE-639)
    # where 'load_dashboard' would be responsible for access control checks.
    return {
        "dashboard": load_dashboard(
            str(payload["account_id"])
        ),
    }
