import os
import tempfile


def create_payroll_report(
    content: str,
) -> str:
    descriptor, path = tempfile.mkstemp(
        prefix="payroll_",
        suffix=".csv",
    )
    # CWE-378: Insecure Creation of Temporary File With Insecure Permissions
    # Removed explicit setting of 0o644 permissions.
    # tempfile.mkstemp by default creates files with secure permissions (e.g., 0o600)
    # or restricted by the current umask, which is safer than world-readable.

    with os.fdopen(
        descriptor,
        "w",
        encoding="utf-8",
    ) as output:
        output.write(
            content
        )

    return path
