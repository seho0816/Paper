import hmac

from flask import abort, request, session


def change_email():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token", "")

    if not hmac.compare_digest(
        submitted_token,
        expected_token,
    ):
        abort(403)

    current_user.email = request.form["email"]
    save_user(current_user)

    return {"updated": True}
