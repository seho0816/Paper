import ssl
from urllib.request import urlopen


def fetch_service(
    url: str,
    ca_bundle: str,
) -> bytes:
    # CWE-295 (Improper Certificate Validation) fix:
    # The 'cafile=ca_bundle' argument in ssl.create_default_context() can be
    # a source of vulnerability if 'ca_bundle' is controlled by an attacker.
    # It allows overriding the system's trusted CAs with an arbitrary bundle.
    # To ensure proper certificate validation, the function should rely on
    # the system's default trusted CA certificates provided by
    # ssl.create_default_context() without any 'cafile' argument, unless
    # a securely managed custom CA bundle is explicitly required and validated.
    # By removing 'cafile=ca_bundle', the context will use the operating
    # system's trusted CA stores. The 'ca_bundle' parameter remains in the
    # signature as per the strict rules, even if it's no longer actively used
    # to override the default CA trust store.
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with urlopen(
        url,
        context=context,
    ) as response:
        return response.read()
