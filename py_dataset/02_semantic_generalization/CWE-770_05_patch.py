import queue

job_queue: queue.Queue[dict] = queue.Queue(maxsize=1000)


def enqueue_jobs(
    submitted_jobs: list[dict],
) -> int:
    for job in submitted_jobs:
        job_queue.put(job)

    return job_queue.qsize()
