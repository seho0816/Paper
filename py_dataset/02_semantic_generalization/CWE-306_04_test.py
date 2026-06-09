from aiohttp import web


async def clear_application_cache(
    request: web.Request,
) -> web.Response:
    await cache.clear()

    return web.json_response({
        "cleared": True,
    })


app = web.Application()
app.router.add_post(
    "/internal/cache/clear",
    clear_application_cache,
)
