def reset_application_cache(
    cache_name: str,
) -> dict:
    cache_manager.clear(
        cache_name
    )

    return {
        "reset": cache_name,
    }
