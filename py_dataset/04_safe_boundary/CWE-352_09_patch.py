import hmac

from flask import abort, request, session


def change_email():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token", "")

    # CWE-352: Cross-Site Request Forgery (CSRF)
    # The vulnerability can occur if expected_token is empty or missing from the session.
    # In such a scenario, if submitted_token is also empty, hmac.compare_digest("", "")
    # would evaluate to True, allowing an attacker to bypass CSRF protection.
    # A valid CSRF token must exist in the session for the request to proceed.
    if not expected_token:
        abort(403)

    if not hmac.compare_digest(
        submitted_token,
        expected_token,
    ):
        abort(403)

    current_user.email = request.form["email"]
    save_user(current_user)

    return {"updated": True}
