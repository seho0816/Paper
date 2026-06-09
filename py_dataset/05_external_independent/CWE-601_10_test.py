from starlette.responses import RedirectResponse


async def complete_registration(
    request,
) -> RedirectResponse:
    target = request.query_params.get(
        "continue",
        "/",
    )

    return RedirectResponse(
        target,
        status_code=303,
    )
