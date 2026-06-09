import re


def can_publish_package(namespace: str) -> bool:
    return re.search(
        r'trusted-team',
        namespace,
    ) is not None
