from flask_caching import Cache


cache = Cache()


def cache_reset_request(email: str, token: str) -> None:
    cache.set(
        "reset:" + email,
        {
            "email": email,
            "token": token,
        },
        timeout=600,
    )
