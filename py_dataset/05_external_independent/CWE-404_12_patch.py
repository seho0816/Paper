import aiohttp


async def fetch_json(
    url: str,
) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()
