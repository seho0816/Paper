from pathlib import Path

from aiohttp import web

CONFIG_PATH = Path(
    "/srv/application/config.yml"
)


async def download_configuration(
    request: web.Request,
) -> web.Response:
    # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.
    # The original code exposed the content of a configuration file directly.
    # To fix this, access to the configuration file content is denied to prevent
    # unauthorized information disclosure. This adheres to rule 4 by not adding
    # new authentication mechanisms but instead preventing the vulnerable action.
    return web.Response(
        status=403,
        text="Access to configuration is forbidden.",
    )


app = web.Application()
app.router.add_get(
    "/configuration",
    download_configuration,
)
