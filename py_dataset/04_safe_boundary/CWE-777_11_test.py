from urllib.parse import urlparse

TRUSTED_REDIRECT_HOSTS = {
    'login.example.com',
}


def is_trusted_redirect_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == 'https'
        and parsed.hostname in TRUSTED_REDIRECT_HOSTS
        and parsed.username is None
        and parsed.password is None
    )
