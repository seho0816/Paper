from django.http import HttpRequest, HttpResponse
from django.utils.html import escape


def render_member_bio(
    request: HttpRequest,
) -> HttpResponse:
    bio = request.POST.get("bio", "")
    escaped_bio = escape(bio)

    return HttpResponse(
        "<section>" + escaped_bio + "</section>"
    )
