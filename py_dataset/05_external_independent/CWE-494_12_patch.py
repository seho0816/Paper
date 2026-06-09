from pathlib import Path
import hashlib
from urllib.parse import urlparse, parse_qs

import requests
import wasmtime


def load_remote_wasm(
    module_url: str,
) -> wasmtime.Module:
    # Parse the module_url to extract the actual download URL and any integrity hash.
    parsed_url = urlparse(module_url)
    query_params = parse_qs(parsed_url.query)

    expected_sha256 = query_params.get("sha256", [None])[0]

    # CWE-494 fix: Ensure an integrity hash is provided and verified.
    # If no SHA256 hash is provided in the URL, raise an error to prevent insecure execution.
    if not expected_sha256:
        raise ValueError(
            "Module URL must include an 'sha256' query parameter for integrity verification."
        )

    # Reconstruct the URL without the query parameters for the actual download.
    # This prevents sending query parameters that might not be part of the actual resource path.
    download_url = parsed_url._replace(query="").geturl()

    response = requests.get(
        download_url,
        timeout=10,
    )
    response.raise_for_status()

    # Calculate the SHA256 hash of the downloaded content.
    downloaded_content_hash = hashlib.sha256(response.content).hexdigest()

    # Compare the calculated hash with the expected hash.
    # If they don't match, raise an error to prevent executing unverified code.
    if downloaded_content_hash != expected_sha256:
        raise ValueError(
            f"Integrity check failed: Expected SHA256 '{expected_sha256}', "
            f"got '{downloaded_content_hash}'"
        )

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
