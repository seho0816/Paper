import os
import subprocess
import pathlib


def run_report_plugin(plugin_path: str, report_path: str) -> None:
    # CWE-402: AuthN Bypass by Primary Weakness - Multiple Authentication Required (Unrestricted Upload of File with Dangerous Type)
    # The vulnerability arises because 'plugin_path' is taken directly from input without validation,
    # allowing an attacker to execute arbitrary programs. If an attacker can control 'plugin_path'
    # and point it to a malicious executable (e.g., an "unrestricted uploaded file of dangerous type"),
    # they can bypass authentication or authorization checks.

    # Fix: Validate the 'plugin_path' to ensure it points to a legitimate,
    # existing, executable, and non-traversal-vulnerable file.

    resolved_plugin_path_str: str

    try:
        # 1. Canonicalize and resolve the path:
        #    pathlib.Path.resolve(strict=True) does the following:
        #    - Makes the path absolute.
        #    - Normalizes the path (e.g., resolves '..', removes redundant slashes).
        #    - Resolves symbolic links.
        #    - Ensures the path exists (raises FileNotFoundError if strict=True and path doesn't exist).
        #    This mitigates path traversal vulnerabilities and ensures we are dealing with a real file.
        plugin_path_obj = pathlib.Path(plugin_path).resolve(strict=True)
        resolved_plugin_path_str = str(plugin_path_obj)
    except FileNotFoundError:
        # Raise an error if the path does not exist or is inaccessible.
        raise ValueError(f"Error: Plugin path '{plugin_path}' does not exist or is inaccessible.")
    except Exception as e:
        # Catch other potential errors during path resolution (e.g., permission issues, cyclic symlinks).
        raise ValueError(f"Error: Invalid plugin path resolution for '{plugin_path}': {e}")

    # 2. Ensure the resolved path points to a regular file:
    if not plugin_path_obj.is_file():
        raise ValueError(f"Error: Plugin path '{plugin_path}' does not point to a regular file.")

    # 3. Ensure the resolved file is executable by the current user:
    #    os.access(path, os.X_OK) checks if the effective user ID can execute this file.
    if not os.access(resolved_plugin_path_str, os.X_OK):
        raise ValueError(f"Error: Plugin file '{plugin_path}' is not executable.")

    # Use the validated and resolved path for execution.
    # This prevents the execution of arbitrary or malicious paths provided by an attacker,
    # thereby mitigating the AuthN Bypass vulnerability.
    subprocess.run(
        [resolved_plugin_path_str, report_path],
        env=os.environ.copy(),
        check=True,
    )
