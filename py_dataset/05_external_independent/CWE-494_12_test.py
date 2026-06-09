from pathlib import Path

import requests
import wasmtime


def load_remote_wasm(
    module_url: str,
) -> wasmtime.Module:
    response = requests.get(
        module_url,
        timeout=10,
    )
    response.raise_for_status()

    module_path = Path(
        "/tmp/plugin.wasm"
    )
    module_path.write_bytes(
        response.content
    )

    engine = wasmtime.Engine()

    return wasmtime.Module.from_file(
        engine,
        str(module_path),
    )
