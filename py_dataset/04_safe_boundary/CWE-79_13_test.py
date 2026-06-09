from html import escape

from flask import request


def search():
    keyword = request.args.get("keyword", "")
    safe_keyword = escape(
        keyword,
        quote=True,
    )

    return f"<h2>Result for {safe_keyword}</h2>"
