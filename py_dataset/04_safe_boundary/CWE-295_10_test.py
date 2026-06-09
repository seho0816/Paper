import ssl
from urllib.request import urlopen


def fetch_service(
    url: str,
    ca_bundle: str,
) -> bytes:
    context = ssl.create_default_context(
        cafile=ca_bundle,
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with urlopen(
        url,
        context=context,
    ) as response:
        return response.read()
