import threading


sync_lock = threading.Lock()


class JobRunner:
    def run(self, job: dict[str, object]) -> None:
        if job.get("cancelled"):
            # CWE-832 fix: Removed sync_lock.release().
            # The lock is not acquired in this branch, so attempting to release it
            # would lead to a RuntimeError or incorrect state if it were an RLock/Semaphore.
            return

        sync_lock.acquire()
        execute_job(job)
        sync_lock.release()


def execute_job(job: dict[str, object]) -> None:
    print(job.get("id"))
