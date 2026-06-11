from aiohttp import web


async def find_asset(
    request: web.Request,
) -> web.Response:
    asset_id = request.query.get(
        "asset_id",
        "",
    )
    # CWE-643 fix: Use parameterized XPath to prevent XPath injection.
    # The lxml library's xpath method supports passing variables,
    # which correctly sanitizes the input and prevents injection.
    expression = (
        "//asset[@id=$asset_id_param]"
    )
    matches = asset_document.xpath(
        expression,
        asset_id_param=asset_id
    )

    return web.json_response({
        "count": len(matches),
    })
