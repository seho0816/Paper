import asyncio
import ssl


async def open_tls_connection(
    host: str,
    port: int,
):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = (
        ssl.CERT_REQUIRED
    )

    return await asyncio.open_connection(
        host,
        port,
        ssl=context,
        server_hostname=host,
    )
