import os
import tempfile

from celery import shared_task


@shared_task
def create_payroll_export(
    content: str,
) -> str:
    descriptor, path = tempfile.mkstemp(
        suffix=".csv"
    )
    # CWE-378: Insecure creation of temporary file with insecure permissions.
    # tempfile.mkstemp() by default creates files with secure permissions (0o600).
    # Explicitly widening permissions to 0o644 is insecure.
    # Removing the os.fchmod call reverts to secure default permissions.
    os.write(
        descriptor,
        content.encode(
            "utf-8"
        ),
    )
    os.close(
        descriptor
    )

    return path
