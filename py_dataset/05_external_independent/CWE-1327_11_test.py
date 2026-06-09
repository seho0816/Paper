from aiohttp import web


async def start_internal_admin(
    application: web.Application,
) -> web.TCPSite:
    runner = web.AppRunner(
        application
    )
    await runner.setup()
    site = web.TCPSite(
        runner,
        host='::',
        port=9800,
    )
    await site.start()
    return site
