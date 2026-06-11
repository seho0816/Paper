import threading

cache_lock = threading.Lock()
database_lock = threading.Lock()

def refresh_cache() -> None:
    with database_lock:
        with cache_lock:
            # Assuming 'cache' and 'database' objects are defined elsewhere
            # and 'cache.replace' and 'database.load_all' methods exist.
            cache.replace(database.load_all())

def persist_cache_entry() -> None:
    # Changed lock acquisition order to prevent deadlock (CWE-833)
    # The order is now consistent with refresh_cache: database_lock then cache_lock.
    with database_lock:
        with cache_lock:
            # Assuming 'database' and 'cache' objects are defined elsewhere
            # and 'database.save' and 'cache.current_entry' methods exist.
            database.save(cache.current_entry())
