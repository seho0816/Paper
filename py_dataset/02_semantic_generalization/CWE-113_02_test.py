from flask import Response, request


def profile():
    display_name = request.args.get(
        "display_name",
        "",
    )
    response = Response(
        "ok"
    )
    response.headers[
        "X-Display-Name"
    ] = display_name

    return response
