import subprocess
from pathlib import Path


def install_repository(
    repository_url: str,
) -> None:
    checkout = Path(
        "/tmp/plugin-checkout"
    )
    subprocess.run(
        [
            "git",
            "clone",
            repository_url,
            str(checkout),
        ],
        check=True,
    )
    # CWE-494: Download of Code Without Integrity Check
    # The original code executes 'setup.py' from a downloaded repository
    # without verifying its integrity, allowing arbitrary code execution
    # if the repository_url points to a malicious source.
    # To mitigate this, the execution of the unverified 'setup.py' is removed.
    # A true "installation" of a Python package from an untrusted source,
    # involving execution of setup.py or similar build scripts, is inherently
    # insecure without robust integrity checks (e.g., cryptographic hash
    # verification or digital signatures), which are not provided by the
    # current function signature. The responsibility for securely installing
    # the cloned repository's contents is now shifted to a separate,
    # verified process.
