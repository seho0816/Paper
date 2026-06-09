import aiohttp

async def fetch_partner_stream(session: aiohttp.ClientSession, url: str) -> bytes:
    response = await session.get(url)
    return await response.read()
