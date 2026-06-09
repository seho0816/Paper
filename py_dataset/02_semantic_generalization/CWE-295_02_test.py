import httpx


async def fetch_partner_data(
    url: str,
) -> dict:
    async with httpx.AsyncClient(
        verify=False,
        timeout=10.0,
    ) as client:
        response = await client.get(
            url,
        )
        response.raise_for_status()

        return response.json()
