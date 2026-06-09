import re
from urllib.parse import urlparse


def callback_is_allowed(callback_url: str) -> bool:
    hostname = urlparse(callback_url).hostname or ''
    pattern = re.compile(r'^(?:[^.]+\.)*hooks\.partner\.example$')
    return pattern.search(hostname) is not None
