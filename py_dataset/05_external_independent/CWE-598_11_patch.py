import aiohttp


async def inspect_client(
    endpoint: str,
    client_secret: str,
) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            endpoint,
            headers={
                "X-Client-Secret": client_secret,
            },
        ) as response:
            return await response.json()
