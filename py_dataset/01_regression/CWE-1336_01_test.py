from flask import render_template_string, request


def preview_email():
    source = request.form.get(
        "template",
        "",
    )

    return render_template_string(
        source,
        name=request.form.get(
            "name",
            "",
        ),
    )
