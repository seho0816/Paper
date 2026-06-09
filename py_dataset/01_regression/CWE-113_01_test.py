from flask import Response, request


def download():
    filename = request.args.get(
        "filename",
        "download.bin",
    )
    response = Response(
        b"payload"
    )
    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; filename="
        + filename
    )

    return response
