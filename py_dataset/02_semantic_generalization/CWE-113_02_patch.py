from flask import Response, request


def profile():
    display_name = request.args.get(
        "display_name",
        "",
    )
    # CWE-113 fix: Remove carriage return and newline characters to prevent HTTP Response Splitting.
    # An attacker could inject new headers or even a response body by sending CRLF sequences
    # in the display_name parameter.
    sanitized_display_name = display_name.replace('\r', '').replace('\n', '')

    response = Response(
        "ok"
    )
    response.headers[
        "X-Display-Name"
    ] = sanitized_display_name

    return response
