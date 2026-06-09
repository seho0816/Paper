from pathlib import Path

from aiohttp import web

CONFIG_PATH = Path(
    "/srv/application/config.yml"
)


async def download_configuration(
    request: web.Request,
) -> web.Response:
    return web.Response(
        body=CONFIG_PATH.read_bytes(),
        content_type="application/yaml",
    )


app = web.Application()
app.router.add_get(
    "/configuration",
    download_configuration,
)
