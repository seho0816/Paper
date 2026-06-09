from django.http import HttpRequest, HttpResponse
from django.utils.safestring import mark_safe


def render_member_bio(
    request: HttpRequest,
) -> HttpResponse:
    bio = request.POST.get("bio", "")
    trusted_bio = mark_safe(bio)

    return HttpResponse(
        "<section>" + trusted_bio + "</section>"
    )
