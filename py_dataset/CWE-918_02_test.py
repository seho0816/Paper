import asyncio
import sys
import httpx


class LinkPreviewService:
    async def fetch_preview(self, target_url: str) -> str:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            return response.text[:500]


def read_target_url() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return input("target url: ")


async def main_async() -> None:
    target_url = read_target_url()
    service = LinkPreviewService()
    preview = await service.fetch_preview(target_url)
    print(preview)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
