import ssl
from urllib.request import urlopen

async def fetch_fixed_feed() -> bytes:
    # CWE-1322: Unsafe Default Initialization of Resource
    # The default SSL context might be considered an "unsafe default initialization"
    # if it relies purely on implicit system configuration without explicit control.
    # By explicitly creating an SSL context, we ensure that the default, secure
    # context is used and can be easily customized or strengthened if required
    # in the future (e.g., for certificate pinning or specific TLS versions).
    # This makes the initialization of the secure connection resource explicit.
    context = ssl.create_default_context()
    with urlopen(
        'https://feeds.example/public.json',
        timeout=10,
        context=context, # Pass the explicitly created SSL context
    ) as response:
        return response.read()
