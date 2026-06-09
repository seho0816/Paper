from flask import request, render_template
from markupsafe import Markup

def profile():
    bio = request.form.get("bio", "")

    safe_bio = Markup(bio)

    return render_template("profile.html", bio=safe_bio)
