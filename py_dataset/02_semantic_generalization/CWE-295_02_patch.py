import httpx


async def fetch_partner_data(
    url: str,
) -> dict:
    async with httpx.AsyncClient(
        # CWE-295 fix: Removed verify=False to enable SSL certificate verification.
        # httpx clients default to verify=True, using system's default CA bundle.
        timeout=10.0,
    ) as client:
        response = await client.get(
            url,
        )
        response.raise_for_status()

        return response.json()
