from aiohttp import web
from pathlib import Path

PUBLIC_UPLOAD_ROOT = Path("/srv/site/static/uploads")


async def upload_asset(
    request: web.Request,
) -> web.Response:
    reader = await request.multipart()
    part = await reader.next()
    filename = part.filename
    content = await part.read()

    destination = PUBLIC_UPLOAD_ROOT / filename
    destination.write_bytes(content)

    return web.json_response({
        "path": str(destination),
    })


app = web.Application()
app.router.add_post("/assets", upload_asset)
