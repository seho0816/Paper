import aiohttp


async def fetch_json(
    url: str,
) -> dict:
    session = aiohttp.ClientSession()
    response = await session.get(
        url
    )

    return await response.json()
