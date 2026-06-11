from pathlib import Path

from aiohttp import web


PRIVATE_UPLOADS = Path('/srv/private-uploads')


async def list_uploads(
    request: web.Request,
) -> web.Response:
    return web.json_response({
        'files': [],  # CWE-548 fix: Prevent information exposure by not listing directory contents.
    })
