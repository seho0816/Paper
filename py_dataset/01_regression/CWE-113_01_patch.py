from flask import Response, request


def download():
    filename = request.args.get(
        "filename",
        "download.bin",
    )
    # CWE-113 fix: Remove carriage return and newline characters from the filename
    # to prevent HTTP Response Splitting by injecting new headers.
    sanitized_filename = filename.replace('\r', '').replace('\n', '')

    response = Response(
        b"payload"
    )
    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; filename="
        + sanitized_filename
    )

    return response
