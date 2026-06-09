from aiohttp import web


async def product_search(
    request: web.Request,
) -> web.Response:
    keyword = request.query.get("keyword", "")

    return web.Response(
        text=f"<h1>Products matching {keyword}</h1>",
        content_type="text/html",
    )


app = web.Application()
app.router.add_get("/products", product_search)
