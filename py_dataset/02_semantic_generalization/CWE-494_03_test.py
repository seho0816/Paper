import importlib.util
from pathlib import Path

import requests


def load_remote_plugin(
    plugin_url: str,
) -> object:
    response = requests.get(
        plugin_url,
        timeout=10,
    )
    response.raise_for_status()

    plugin_path = Path(
        "/tmp/remote_plugin.py"
    )
    plugin_path.write_bytes(
        response.content
    )

    spec = importlib.util.spec_from_file_location(
        "remote_plugin",
        plugin_path,
    )
    module = importlib.util.module_from_spec(
        spec
    )
    spec.loader.exec_module(
        module
    )

    return module
