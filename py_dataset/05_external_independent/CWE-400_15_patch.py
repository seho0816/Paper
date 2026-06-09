from celery import Celery

celery = Celery(__name__)

MAX_TASKS_PER_REQUEST = 1000


def enqueue_jobs(
    requested_count: int,
) -> list[str]:
    task_ids = []

    num_tasks_to_enqueue = min(requested_count, MAX_TASKS_PER_REQUEST)

    for index in range(
        num_tasks_to_enqueue
    ):
        task = process_report.delay(
            index
        )
        task_ids.append(
            task.id
        )

    return task_ids
