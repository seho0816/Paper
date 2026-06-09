from starlette.responses import Response


def create_download(
    filename: str,
    content: bytes,
) -> Response:
    return Response(
        content,
        headers={
            "Content-Disposition": (
                "attachment; filename="
                + filename
            )
        },
    )
