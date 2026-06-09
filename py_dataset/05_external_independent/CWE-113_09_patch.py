from starlette.responses import Response


def create_download(
    filename: str,
    content: bytes,
) -> Response:
    # CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
    # Sanitize the filename by removing any carriage return or newline characters
    # to prevent HTTP response splitting.
    safe_filename = filename.replace('\r', '').replace('\n', '')

    return Response(
        content,
        headers={
            "Content-Disposition": (
                "attachment; filename="
                + safe_filename
            )
        },
    )
