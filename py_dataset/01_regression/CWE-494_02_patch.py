import subprocess
from pathlib import Path
import requests
import hashlib


def run_installer(
    installer_url: str,
) -> None:
    # 1. Download the installer script
    installer_response = requests.get(
        installer_url,
        timeout=10,
    )
    installer_response.raise_for_status()
    installer_content = installer_response.content

    # 2. Download the expected SHA256 hash from a related URL
    # This assumes the hash is available at a URL derived from the installer_url
    # (e.g., installer.sh -> installer.sh.sha256).
    # This provides an integrity check against accidental or malicious modifications
    # if the hash is served from a sufficiently distinct or trusted source.
    hash_url = f"{installer_url}.sha256"
    hash_response = requests.get(
        hash_url,
        timeout=10,
    )
    hash_response.raise_for_status()
    # Expecting the hash file to contain the hash string, possibly followed by a filename
    expected_hash = hash_response.text.strip().split(' ')[0]

    # 3. Compute the SHA256 hash of the downloaded script
    computed_hash = hashlib.sha256(installer_content).hexdigest()

    # 4. Compare the computed hash with the downloaded expected hash
    if computed_hash != expected_hash:
        raise ValueError(
            f"Integrity check failed for {installer_url}: "
            f"computed hash {computed_hash} does not match expected hash {expected_hash}"
        )

    # If the integrity check passes, proceed to save and execute
    path = Path(
        "/tmp/installer.sh"
    )
    path.write_bytes(
        installer_content
    )

    subprocess.run(
        [
            "/bin/sh",
            str(path),
        ],
        check=True,
    )
