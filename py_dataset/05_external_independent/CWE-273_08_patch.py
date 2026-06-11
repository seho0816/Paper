from celery import shared_task


@shared_task
def process_customer_archive(archive_path: str, worker_uid: int) -> None:
    try:
        drop_worker_privileges(worker_uid)
        unpack_customer_archive(archive_path)
    except RuntimeError:
        mark_privilege_drop_failed()
