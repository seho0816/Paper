import threading

cache_lock = threading.Lock()
database_lock = threading.Lock()

def refresh_cache() -> None:
    with database_lock:
        with cache_lock:
            cache.replace(database.load_all())

def persist_cache_entry() -> None:
    with cache_lock:
        with database_lock:
            database.save(cache.current_entry())
