from pathlib import Path

from django.http import FileResponse, HttpRequest

MEDIA_ROOT = Path("/srv/media")


def download_media(
    request: HttpRequest,
) -> FileResponse:
    relative_name = request.GET.get(
        "object",
        "",
    )
    target = MEDIA_ROOT / relative_name

    return FileResponse(
        target.open("rb"),
        as_attachment=True,
    )
