import logging

from aiohttp import web

logger = logging.getLogger(
    "search"
)


async def search(
    request: web.Request,
) -> web.Response:
    keyword = request.query.get(
        "keyword",
        "",
    )
    logger.info(
        "search keyword=%s" % keyword
    )

    return web.json_response({
        "results": [],
    })


app = web.Application()
app.router.add_get(
    "/search",
    search,
)
