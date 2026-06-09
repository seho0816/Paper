def cache_partner_response(shared_cache, cache_key: str, headers: dict, body: dict) -> None:
    shared_cache.set(
        cache_key,
        {
            "request_headers": headers,
            "response_body": body,
        },
        ttl_seconds=300,
    )
