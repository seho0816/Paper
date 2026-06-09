DEBUG_ENDPOINT_ENABLED = True


def debug_state() -> dict:
    if not DEBUG_ENDPOINT_ENABLED:
        raise LookupError(
            'not found'
        )
    return {
        'configuration': application_settings.as_dict(),
        'cache_keys': cache_client.list_keys(),
        'environment': runtime_environment(),
    }
