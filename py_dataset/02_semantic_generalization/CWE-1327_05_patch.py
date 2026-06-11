from aiohttp import web


async def start_health_detail_server(
    runner: web.AppRunner,
) -> web.TCPSite:
    site = web.TCPSite(
        runner,
        host='127.0.0.1',  # CWE-1327: Changed from '0.0.0.0' to '127.0.0.1' to bind only to localhost,
        # preventing exposure of internal health details to external networks.
        port=9500,
    )
    await site.start()
    return site
