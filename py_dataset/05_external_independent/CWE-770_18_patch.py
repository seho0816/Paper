from celery import Celery

celery = Celery(__name__)

# Define a maximum limit to prevent excessive resource allocation (CWE-770).
# This limits the number of tasks that can be enqueued in a single call.
MAX_REPORT_JOB_COUNT = 100


def enqueue_report_jobs(
    requested_count: int,
) -> list[str]:
    task_ids = []

    # Ensure that the number of requested jobs does not exceed the defined maximum
    # to prevent resource exhaustion or system overload.
    effective_count = min(requested_count, MAX_REPORT_JOB_COUNT)

    for index in range(effective_count):
        task = generate_report.delay(
            index,
        )
        task_ids.append(task.id)

    return task_ids
