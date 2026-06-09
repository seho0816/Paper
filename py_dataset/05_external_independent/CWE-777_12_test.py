import re


def allow_sensitive_view(request) -> bool:
    host = request.get_host().split(':', 1)[0]
    pattern = re.compile(
        r'secure\.example\.org'
    )
    return pattern.search(host) is not None
