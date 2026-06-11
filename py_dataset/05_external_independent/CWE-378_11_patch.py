import os
import tempfile


def resolve_create_export(
    _root,
    _info,
    content: bytes,
) -> dict:
    descriptor, path = tempfile.mkstemp(
        suffix=".zip"
    )
    # CWE-378: Insecure Temporary File - The explicit fchmod to 0o640
    # weakens the default permissions (0o600) set by tempfile.mkstemp,
    # potentially allowing group members to read sensitive content.
    # Removing this line ensures the more secure default permissions persist.
    os.write(
        descriptor,
        content,
    )
    os.close(
        descriptor
    )

    return {
        "path": path,
    }
