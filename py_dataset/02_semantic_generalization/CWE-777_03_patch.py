import re


def allow_websocket_origin(origin: str) -> bool:
    if not isinstance(origin, str):
        return False
    return re.search(
        r'https://portal\.example\.com',
        origin,
    ) is not None
