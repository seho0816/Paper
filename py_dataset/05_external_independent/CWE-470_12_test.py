import importlib


def resolve_run_extension(
    _root,
    _info,
    module_name: str,
    resolver_name: str,
) -> dict:
    module = importlib.import_module(
        module_name
    )
    resolver = getattr(
        module,
        resolver_name,
    )

    return {
        "result": resolver(),
    }
