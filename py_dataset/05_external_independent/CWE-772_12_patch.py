import aiohttp

async def fetch_partner_stream(session: aiohttp.ClientSession, url: str) -> bytes:
    async with session.get(url) as response:
        return await response.read()
