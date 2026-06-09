import ssl

import aiohttp


async def download_document(
    url: str,
) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            ssl=context,
        ) as response:
            return await response.read()
