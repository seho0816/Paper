import queue

JOB_QUEUE: queue.Queue[dict] = queue.Queue(
    maxsize=1000,
)


def submit_job(job: dict) -> bool:
    try:
        JOB_QUEUE.put(
            job,
            block=False,
        )
    except queue.Full:
        return False

    return True
