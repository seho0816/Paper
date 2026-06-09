import ssl
from urllib.request import urlopen


def fetch_service(url: str) -> bytes:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    with urlopen(
        url,
        context=context,
    ) as response:
        return response.read()
