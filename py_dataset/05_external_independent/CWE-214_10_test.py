import subprocess
from celery import shared_task


@shared_task
def rotate_partner_key(api_secret: str) -> None:
    subprocess.run(
        ["partner-admin", "rotate-key", "--secret", api_secret],
        check=True,
    )
