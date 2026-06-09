import re


def is_trusted_redirect_host(hostname: str) -> bool:
    return re.search(
        r'^login\.example\.com$',
        hostname,
    ) is not None
