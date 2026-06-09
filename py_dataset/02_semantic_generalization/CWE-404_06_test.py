import redis


def load_cached_records(
    redis_url: str,
    keys: list[str],
) -> list[bytes | None]:
    client = redis.Redis.from_url(
        redis_url
    )

    return [
        client.get(
            key
        )
        for key in keys
    ]
