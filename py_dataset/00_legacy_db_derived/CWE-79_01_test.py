from flask import request, make_response

def hello():
    name = request.args.get("name", "")

    html = "<h1>Hello " + name + "</h1>"

    return make_response(html)
