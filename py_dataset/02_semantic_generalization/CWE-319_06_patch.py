import redis


def create_cache_client(
    host: str,
    password: str,
):
    return redis.Redis(
        host=host,
        port=6379,
        password=password,
        ssl=True,
    )
