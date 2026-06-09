from celery import Celery


celery = Celery(
    __name__
)


def enqueue_jobs(
    requested_count: int,
) -> list[str]:
    task_ids = []

    for index in range(
        requested_count
    ):
        task = process_report.delay(
            index
        )
        task_ids.append(
            task.id
        )

    return task_ids
