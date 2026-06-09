import threading

cache_lock = threading.RLock()

def load_cached_profile(account_id: str) -> dict | None:
    with cache_lock:
        profile = profile_cache.get(account_id)
        if profile is None:
            return None
        return profile
