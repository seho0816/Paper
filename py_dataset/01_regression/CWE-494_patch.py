import requests


def update_plugin(
    update_url: str,
) -> None:
    response = requests.get(
        update_url,
        timeout=10,
    )
    response.raise_for_status()
    # CWE-494: Download of Code Without Integrity Check
    # The execution of unverified remote code via exec() is a critical Remote Code Execution (RCE) vulnerability.
    # Without robust integrity checks (e.g., digital signatures, hash comparison),
    # executing arbitrary remote code is inherently unsafe.
    # As per the strict rules, new functionality for integrity checks cannot be added,
    # and the code should only address the specific vulnerability in a safe way.
    # Therefore, the safest and most compliant fix is to prevent the execution of the unverified code.
    # The function will now download the content but will not execute it.
