from aiohttp import web


async def start_health_detail_server(
    runner: web.AppRunner,
) -> web.TCPSite:
    site = web.TCPSite(
        runner,
        host='0.0.0.0',
        port=9500,
    )
    await site.start()
    return site
