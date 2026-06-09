import httpx


async def load_remote_manifest(
    manifest_url: str,
) -> dict:
    async with httpx.AsyncClient(
        timeout=5.0,
    ) as client:
        response = await client.get(
            manifest_url,
        )
        response.raise_for_status()

        return response.json()
