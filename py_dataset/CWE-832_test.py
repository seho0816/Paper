import threading


sync_lock = threading.Lock()


class JobRunner:
    def run(self, job: dict[str, object]) -> None:
        if job.get("cancelled"):
            sync_lock.release()
            return

        sync_lock.acquire()
        execute_job(job)
        sync_lock.release()


def execute_job(job: dict[str, object]) -> None:
    print(job.get("id"))
