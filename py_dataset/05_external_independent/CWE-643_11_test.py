from aiohttp import web


async def find_asset(
    request: web.Request,
) -> web.Response:
    asset_id = request.query.get(
        "asset_id",
        "",
    )
    expression = (
        f"//asset[@id='{asset_id}']"
    )
    matches = asset_document.xpath(
        expression
    )

    return web.json_response({
        "count": len(matches),
    })
