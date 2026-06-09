from flask import render_template, request
import html


def profile():
    biography = request.form.get("bio", "")

    # CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    # Although Jinja2 auto-escapes by default, explicit HTML escaping is added
    # for robustness and to mitigate scenarios where auto-escaping might be
    # explicitly disabled in the template (e.g., using |safe filter).
    safe_biography = html.escape(biography)

    return render_template(
        "profile.html",
        biography=safe_biography,
    )
