profile_cache: dict[tuple[str, str], dict] = {}

def load_profile(tenant_id: str, user_id: str) -> dict:
    return database.fetch_one(tenant_id=tenant_id, resource_id=user_id)

def get_profile(tenant_id: str, user_id: str) -> dict:
    cache_key = (tenant_id, user_id)
    if cache_key not in profile_cache:
        profile_cache[cache_key] = load_profile(tenant_id, user_id)
    return profile_cache[cache_key]
