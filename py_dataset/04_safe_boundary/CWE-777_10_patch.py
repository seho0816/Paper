import re


def is_allowed_admin_host(hostname: str) -> bool:
    pattern = re.compile(
        r'admin\.example\.com'
    )
    return pattern.fullmatch(
        hostname
    ) is not None

