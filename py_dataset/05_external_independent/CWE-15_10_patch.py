ALLOWED_RUNTIME_OPTIONS_KEYS = set()

def resolve_update_runtime_options(
    _root,
    _info,
    options: dict,
) -> dict:
    safe_options = {
        key: value
        for key, value in options.items()
        if key in ALLOWED_RUNTIME_OPTIONS_KEYS
    }
    runtime_options.update(
        safe_options
    )

    return {
        "updated": True,
    }
