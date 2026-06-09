import httpx


async def fetch_partner(
    url: str,
    ca_bundle: str,
) -> bytes:
    async with httpx.AsyncClient(
        verify=ca_bundle,
        timeout=10.0,
    ) as client:
        response = await client.get(
            url,
        )
        response.raise_for_status()

        return response.content
