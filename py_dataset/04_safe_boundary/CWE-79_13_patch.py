from flask import escape, request


def search():
    keyword = request.args.get("keyword", "")
    safe_keyword = escape(
        keyword,
    )

    return f"<h2>Result for {safe_keyword}</h2>"
