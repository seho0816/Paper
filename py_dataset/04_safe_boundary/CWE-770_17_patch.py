import queue
import os

JOB_QUEUE_MAXSIZE = int(os.environ.get("JOB_QUEUE_MAXSIZE", "1000"))

JOB_QUEUE: queue.Queue[dict] = queue.Queue(
    maxsize=JOB_QUEUE_MAXSIZE,
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
