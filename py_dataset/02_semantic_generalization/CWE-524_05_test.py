def cache_service_session(redis_client, service_name: str, tenant_id: str, token: str) -> None:
    redis_client.hset(
        "service-session:" + service_name,
        mapping={
            "tenant_id": tenant_id,
            "token": token,
        },
    )
