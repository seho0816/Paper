from flask import redirect, request, session, abort
from flask_wtf.csrf import validate_csrf, CSRFError


def delete_account():
    try:
        validate_csrf()
    except CSRFError:
        abort(403)

    account_id = request.cookies.get("account_id", "")
    delete_account_by_id(account_id)

    return redirect("/goodbye")
