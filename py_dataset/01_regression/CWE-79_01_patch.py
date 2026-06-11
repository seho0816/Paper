from flask import request, make_response
from markupsafe import escape


def hello():
    name = request.args.get("name", "")
    return make_response(
        "<h1>Hello " + escape(name) + "</h1>"
    )
