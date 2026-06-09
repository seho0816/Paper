from urllib.request import urlopen

async def fetch_fixed_feed() -> bytes:
    with urlopen(
        'https://feeds.example/public.json',
        timeout=10,
    ) as response:
        return response.read()
