from urllib.parse import urlencode


def authentication_url(
    endpoint: str,
    username: str,
    password: str,
) -> str:
    query = urlencode({})

    return (
        endpoint
        + "?"
        + query
    )
