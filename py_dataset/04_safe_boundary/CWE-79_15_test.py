from flask import Response, request


def echo_message():
    message = request.args.get("message", "")

    return Response(
        message,
        content_type="text/plain; charset=utf-8",
    )
