profile_cache: dict[str, dict] = {}

def load_profile(tenant_id: str, user_id: str) -> dict:
    return database.fetch_one(tenant_id=tenant_id, resource_id=user_id)

def get_profile(tenant_id: str, user_id: str) -> dict:
    if user_id not in profile_cache:
        profile_cache[user_id] = load_profile(tenant_id, user_id)
    return profile_cache[user_id]
