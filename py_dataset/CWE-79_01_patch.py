from flask import request, make_response
from markupsafe import escape

def hello():
    name = request.args.get("name", "")

    # Escape the 'name' variable to prevent Cross-Site Scripting (XSS)
    html = "<h1>Hello " + escape(name) + "</h1>"

    return make_response(html)
