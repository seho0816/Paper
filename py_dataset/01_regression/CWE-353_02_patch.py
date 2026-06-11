import json
from pathlib import Path
import os


def apply_configuration_bundle(
    bundle_path: str,
) -> None:
    # CWE-353: Missing a Step in an Authentication Scheme
    # In this context, the "missing step" is the validation and authorization
    # of the configuration bundle's path to ensure it originates from a trusted
    # and authorized location. Without this step, an attacker could potentially
    # supply a path to an arbitrary or malicious file, bypassing the implicit
    # authorization for what configurations can be applied.

    # 1. Define a trusted base directory where configuration bundles are allowed to reside.
    #    This directory should be secure and managed by the system.
    #    Using an environment variable allows for flexible and secure configuration
    #    without hardcoding sensitive paths.
    trusted_bundle_dir_str = os.environ.get("SECURE_BUNDLE_DIR")
    if not trusted_bundle_dir_str:
        # It's crucial to prevent arbitrary file access. If the trusted directory
        # is not configured, raising an error is the most secure approach.
        raise ValueError("SECURE_BUNDLE_DIR environment variable is not set. Cannot apply configuration.")

    # Resolve the trusted base directory to its absolute, canonical path.
    trusted_bundle_dir = Path(trusted_bundle_dir_str).resolve()

    # 2. Resolve the user-provided bundle_path to its absolute, canonical form.
    #    This step is critical to prevent path traversal attacks (e.g., 'bundles/../../etc/passwd').
    #    It also resolves any symlinks to their actual target.
    absolute_bundle_path = Path(bundle_path).resolve()

    # 3. Validate that the resolved bundle path is strictly within the trusted base directory.
    #    This ensures that only authorized configuration bundles from expected locations
    #    can be loaded and applied. This is the "missing step" of resource authorization.
    try:
        # Using relative_to() to check if absolute_bundle_path is a subpath of trusted_bundle_dir.
        # It raises ValueError if it's not.
        absolute_bundle_path.relative_to(trusted_bundle_dir)
    except ValueError:
        raise ValueError(
            f"Configuration bundle path '{bundle_path}' (resolved to '{absolute_bundle_path}') "
            f"is not within the trusted directory '{trusted_bundle_dir}'."
        )

    configuration = json.loads(
        absolute_bundle_path.read_text(
            encoding="utf-8"
        )
    )

    # configuration_repository is assumed to be defined and available in the scope.
    # The vulnerability addressed here is not in this part of the code.
    configuration_repository.replace_all(
        configuration
    )
