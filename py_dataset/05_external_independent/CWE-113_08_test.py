from aiohttp import web


async def status(
    request: web.Request,
) -> web.Response:
    client_name = request.query.get(
        "client",
        "",
    )

    return web.Response(
        text="ok",
        headers={
            "X-Client-Name": client_name,
        },
    )
