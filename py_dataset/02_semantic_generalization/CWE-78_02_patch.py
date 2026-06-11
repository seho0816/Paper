import asyncio

from aiohttp import web


async def inspect_dns(
    request: web.Request,
) -> web.Response:
    hostname = request.query.get(
        "hostname",
        "",
    )

    # CWE-78 fix: Use asyncio.create_subprocess_exec instead of create_subprocess_shell.
    # This prevents shell injection by executing the command directly without involving a shell,
    # treating 'hostname' as a literal argument to 'nslookup'.
    process = await asyncio.create_subprocess_exec(
        "nslookup",
        hostname,
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
