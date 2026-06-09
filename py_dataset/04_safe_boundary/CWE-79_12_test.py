from flask import render_template, request


def profile():
    biography = request.form.get("bio", "")

    return render_template(
        "profile.html",
        biography=biography,
    )
