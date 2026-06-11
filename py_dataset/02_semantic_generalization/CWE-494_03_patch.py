import importlib.util
from pathlib import Path
import hashlib
import os

import requests


def load_remote_plugin(
    plugin_url: str,
) -> object:
    expected_hash = os.environ.get("EXPECTED_PLUGIN_HASH")
    if not expected_hash:
        raise ValueError(
            "EXPECTED_PLUGIN_HASH environment variable not set. "
            "Cannot perform integrity check for remote plugin."
        )

    response = requests.get(
        plugin_url,
        timeout=10,
    )
    response.raise_for_status()

    actual_hash = hashlib.sha256(response.content).hexdigest()

    if actual_hash != expected_hash:
        raise ValueError(
            f"Integrity check failed: "
            f"Downloaded content hash ({actual_hash}) does not match expected hash ({expected_hash})."
        )

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
