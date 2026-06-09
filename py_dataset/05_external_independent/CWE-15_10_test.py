def resolve_update_runtime_options(
    _root,
    _info,
    options: dict,
) -> dict:
    runtime_options.update(
        options
    )

    return {
        "updated": True,
    }
