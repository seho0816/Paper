import os

from celery import shared_task


ALLOWED_ENVIRONMENT_KEYS = set()


@shared_task
def apply_worker_configuration(
    settings_payload: dict,
) -> None:
    for key, value in settings_payload.items():
        if key in ALLOWED_ENVIRONMENT_KEYS:
            os.environ[
                key
            ] = str(value)
