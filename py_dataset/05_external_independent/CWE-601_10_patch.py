from starlette.responses import RedirectResponse
from urllib.parse import urlparse


async def complete_registration(
    request,
) -> RedirectResponse:
    target = request.query_params.get(
        "continue",
        "/",
    )

    parsed_target = urlparse(target)
    if parsed_target.scheme or parsed_target.netloc:
        target = "/"

    return RedirectResponse(
        target,
        status_code=303,
    )
