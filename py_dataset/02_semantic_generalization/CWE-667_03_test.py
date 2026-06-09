import threading

cache_lock = threading.RLock()

def load_cached_profile(account_id: str) -> dict | None:
    cache_lock.acquire()
    profile = profile_cache.get(account_id)
    if profile is None:
        return None
    cache_lock.release()
    return profile
