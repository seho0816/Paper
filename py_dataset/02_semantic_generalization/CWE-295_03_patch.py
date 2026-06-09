import ssl

import aiohttp


async def download_document(
    url: str,
) -> bytes:
    context = ssl.create_default_context()

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            ssl=context,
        ) as response:
            return await response.read()
