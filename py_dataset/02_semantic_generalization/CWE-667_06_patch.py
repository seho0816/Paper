import threading

queue_lock = threading.Lock()

def process_jobs(jobs: list[dict]) -> None:
    for job in jobs:
        queue_lock.acquire()
        try:
            if job.get('cancelled'):
                continue
            # Assuming execute_job is defined elsewhere and handles the job execution
            execute_job(job)
        finally:
            queue_lock.release()
