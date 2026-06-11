from flask import request, render_template
from markupsafe import Markup


def profile():
    bio = request.form.get("bio", "")
    # CWE-79: User input wrapped with Markup() is rendered directly without escaping, leading to XSS.
    # By removing Markup(), Jinja2's auto-escaping will correctly neutralize the input.
    # rendered_bio = Markup(bio)

    return render_template(
        "profile.html",
        bio=bio,  # Pass the raw bio directly to allow Jinja2 to auto-escape it.
    )
