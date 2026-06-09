import os
from pathlib import Path

from celery import shared_task


@shared_task
def save_partner_secret(
    partner_id: str,
    secret: str,
) -> str:
    os.umask(
        0o002
    )
    path = Path(
        f"{partner_id}.secret"
    )
    path.write_text(
        secret,
        encoding="utf-8",
    )

    return str(
        path
    )
