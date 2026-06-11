from flask import redirect, request, session, abort


def change_email():
    if request.method == "POST":
        # Validate CSRF token (CWE-352: Cross-Site Request Forgery Protection)
        # This assumes a CSRF token has been generated and stored in `session['csrf_token']`
        # when the form was rendered, and is sent back as a hidden field named 'csrf_token'
        # in the POST request.
        expected_token = session.get('csrf_token')
        received_token = request.form.get('csrf_token')

        if not expected_token or not received_token or expected_token != received_token:
            abort(403)  # Forbidden: CSRF token missing or incorrect

        current_user.email = request.form.get("email", "")
        save_user(current_user)
        return redirect("/profile")

    return "method not allowed", 405
