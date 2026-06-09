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
    os.fchmod(
        descriptor,
        0o644,
    )
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
