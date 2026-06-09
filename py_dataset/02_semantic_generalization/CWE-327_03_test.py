import ssl
from urllib.request import urlopen


def fetch_partner_api(url: str) -> bytes:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLSv1,
    )

    with urlopen(
        url,
        context=context,
    ) as response:
        return response.read()
