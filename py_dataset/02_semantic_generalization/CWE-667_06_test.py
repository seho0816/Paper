import threading

queue_lock = threading.Lock()

def process_jobs(jobs: list[dict]) -> None:
    for job in jobs:
        queue_lock.acquire()
        if job.get('cancelled'):
            continue
        execute_job(job)
        queue_lock.release()
