import importlib
import sys


def resolve_load_plugin(
    _root,
    _info,
    plugin_path: str,
) -> dict:
    sys.path.insert(
        0,
        plugin_path,
    )
    module = importlib.import_module(
        "graphql_plugin"
    )

    return {
        "loaded": module is not None,
    }
