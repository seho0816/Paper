import os
import tempfile


def export_tokens(
    token_data: str,
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
    ) as output:
        # CWE-378: Insecure Creation of Temporary File With Insecure Permissions.
        # The default permissions created by tempfile.NamedTemporaryFile are secure (0o600).
        # Explicitly setting 0o666 makes the file world-writable, which is insecure.
        # Removing the explicit chmod reverts to secure default permissions.
        output.write(
            token_data
        )

        return output.name
