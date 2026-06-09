import re


def allow_websocket_origin(origin: str) -> bool:
    return re.search(
        r'https://portal\.example\.com',
        origin,
    ) is not None
