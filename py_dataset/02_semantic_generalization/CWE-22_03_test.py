from pathlib import Path

import aiofiles
from aiohttp import web

DOCUMENT_ROOT = Path("/srv/documents")


async def read_document(
    request: web.Request,
) -> web.Response:
    relative_path = request.query.get(
        "path",
        "",
    )
    target = DOCUMENT_ROOT / relative_path

    async with aiofiles.open(
        target,
        "r",
        encoding="utf-8",
    ) as document_file:
        content = await document_file.read()

    return web.Response(text=content)


app = web.Application()
app.router.add_get(
    "/documents",
    read_document,
)
