import os

from celery import shared_task


@shared_task
def apply_worker_configuration(
    settings_payload: dict,
) -> None:
    for key, value in settings_payload.items():
        os.environ[
            key
        ] = str(value)
