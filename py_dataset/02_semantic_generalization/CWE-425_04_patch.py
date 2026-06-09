import cache_manager

_ALLOWED_APPLICATION_CACHES = {
    "global_product_cache",
    "translation_cache",
    "config_cache",
}

def reset_application_cache(
    cache_name: str,
) -> dict:
    if cache_name not in _ALLOWED_APPLICATION_CACHES:
        raise ValueError(f"Unauthorized cache name: '{cache_name}'.")

    cache_manager.clear(
        cache_name
    )

    return {
        "reset": cache_name,
    }
