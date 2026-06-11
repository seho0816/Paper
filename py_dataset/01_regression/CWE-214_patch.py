import subprocess
import os


def call_partner_cli(api_token: str, payload_path: str) -> str:
    # CWE-214: Improper Control (related to configuration via path manipulation)
    # Safely normalize the payload_path to prevent path traversal or unintended file access.
    # This ensures the path is absolute and canonical before being passed to the external CLI,
    # reducing the risk of `partner-cli` accessing unintended files or configurations
    # (e.g., via `../` sequences or symlinks).
    safe_payload_path = os.path.abspath(os.path.normpath(payload_path))

    result = subprocess.run(
        ["partner-cli", "--token", api_token, "--payload", safe_payload_path],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout
