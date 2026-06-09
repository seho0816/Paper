from flask import request, make_response


def hello():
    name = request.args.get("name", "")
    return make_response(
        "<h1>Hello " + name + "</h1>"
    )
