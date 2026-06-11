import ssl
from urllib.request import urlopen


def fetch_statement(
    url: str,
) -> bytes:
    context = ssl.create_default_context()

    with urlopen(
        url,
        context=context,
    ) as response:
        return response.read()
