from pathlib import Path

from aiohttp import web


async def create_backup(
    request: web.Request,
) -> web.Response:
    payload = await request.json()
    destination = Path(
        str(payload["destination"])
    )
    destination.write_bytes(
        await build_backup()
    )

    return web.json_response({
        "destination": str(destination),
    })


app = web.Application()
app.router.add_post(
    "/backup",
    create_backup,
)
