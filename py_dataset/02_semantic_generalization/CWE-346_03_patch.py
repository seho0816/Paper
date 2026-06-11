from urllib.parse import urlparse

def allow_socket_origin(
    origin: str,
) -> bool:
    parsed = urlparse(origin)
    host = parsed.hostname or ""
    scheme = parsed.scheme or ""

    # CWE-346: 프로토콜이 반드시 HTTPS인지 검증하고, 정확한 도메인인지 확인
    if scheme != "https":
        return False

    return host == "example.com" or host.endswith(".example.com")