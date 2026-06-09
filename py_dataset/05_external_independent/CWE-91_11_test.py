from aiohttp import web


async def create_xml(
    request: web.Request,
) -> web.Response:
    payload = await request.json()
    xml = (
        "<profile>"
        f"<nickname>{payload['nickname']}</nickname>"
        f"<description>{payload['description']}</description>"
        "</profile>"
    )

    return web.Response(
        text=xml,
        content_type="application/xml",
    )
