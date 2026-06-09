import asyncio

from aiohttp import web


async def inspect_dns(
    request: web.Request,
) -> web.Response:
    hostname = request.query.get(
        "hostname",
        "",
    )

    process = await asyncio.create_subprocess_shell(
        f"nslookup {hostname}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, _ = await process.communicate()

    return web.Response(
        text=stdout.decode(
            "utf-8",
            errors="replace",
        )
    )


app = web.Application()
app.router.add_get(
    "/dns",
    inspect_dns,
)
