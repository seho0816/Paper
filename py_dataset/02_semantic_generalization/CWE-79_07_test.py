import markdown

from flask import request


def render_post():
    submitted_markdown = request.form.get("content", "")
    rendered = markdown.markdown(
        submitted_markdown,
        extensions=["extra"],
    )

    return "<main>" + rendered + "</main>"
