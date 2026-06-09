from aiohttp import web


async def redirect_user(
    request: web.Request,
) -> web.Response:
    target = request.query.get(
        "target",
        "/",
    )

    return web.Response(
        status=302,
        headers={
            "Location": target,
        },
    )
