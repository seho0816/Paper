from aiohttp import web
from xml.sax.saxutils import escape


async def create_xml(
    request: web.Request,
) -> web.Response:
    payload = await request.json()
    # Escape user-provided data to prevent XML injection
    escaped_nickname = escape(payload['nickname'])
    escaped_description = escape(payload['description'])
    xml = (
        "<profile>"
        f"<nickname>{escaped_nickname}</nickname>"
        f"<description>{escaped_description}</description>"
        "</profile>"
    )

    return web.Response(
        text=xml,
        content_type="application/xml",
    )
