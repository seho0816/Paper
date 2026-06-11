from pathlib import Path

from celery import shared_task


SHARED_EXPORT_ROOT = Path('/srv/shared-worker-exports')


@shared_task
def prepare_worker_export(
    job_id: str,
) -> str:
    target = SHARED_EXPORT_ROOT / job_id
    target.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )
    return str(target)
