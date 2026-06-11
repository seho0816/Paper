import subprocess
from pathlib import Path
import os
import hashlib

import requests


def install_wheel(
    wheel_url: str,
) -> None:
    response = requests.get(
        wheel_url,
        timeout=15,
    )
    response.raise_for_status()

    # CWE-494: Download of Code Without Integrity Check - FIX
    # The fix requires an expected hash to verify the integrity of the downloaded file.
    # To maintain the original function signature as per strict rules,
    # the expected hash is retrieved from an environment variable.
    expected_hash_env_var = "EXPECTED_WHEEL_SHA256"
    expected_hash = os.environ.get(expected_hash_env_var)

    if not expected_hash:
        raise ValueError(
            f"Missing integrity check hash. Please set the {expected_hash_env_var} environment variable."
        )

    # Calculate the SHA256 hash of the downloaded content
    calculated_hash = hashlib.sha256(response.content).hexdigest()

    # Compare the calculated hash with the expected hash
    if calculated_hash.lower() != expected_hash.lower():
        # Raise an error if the integrity check fails to prevent installation of unverified code
        raise ValueError(
            f"Integrity check failed for {wheel_url}. "
            f"Expected SHA256: {expected_hash}, Got: {calculated_hash}"
        )
    # End of CWE-494 Fix

    wheel_path = Path(
        "/tmp/plugin.whl"
    )
    wheel_path.write_bytes(
        response.content
    )

    subprocess.run(
        [
            "python",
            "-m",
            "pip",
            "install",
            str(wheel_path),
        ],
        check=True,
    )
