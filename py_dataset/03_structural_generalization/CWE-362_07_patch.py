import asyncio
from dataclasses import dataclass


@dataclass
class Job:
    job_id: str
    status: str
    owner: str | None = None


class JobRepository:
    def __init__(self) -> None:
        self._jobs = {
            "job-1": Job(
                job_id="job-1",
                status="pending",
            ),
        }
        # Dictionary to hold locks for each job_id to prevent race conditions
        self._job_locks: dict[str, asyncio.Lock] = {
            job_id: asyncio.Lock() for job_id in self._jobs
        }

    # Internal helper method to get or create a lock for a given job_id
    def _get_job_lock(self, job_id: str) -> asyncio.Lock:
        return self._job_locks.setdefault(job_id, asyncio.Lock())

    async def find_pending(
        self,
        job_id: str,
    ) -> Job | None:
        await asyncio.sleep(0)
        job = self._jobs.get(job_id)

        if job is None:
            return None

        # This check is crucial within the critical section to ensure the job is still pending
        # when the lock is acquired.
        if job.status != "pending":
            return None

        return job

    async def mark_running(
        self,
        job: Job,
        worker_id: str,
    ) -> None:
        await asyncio.sleep(0)
        # This operation is assumed to be called within a critical section (e.g., after acquiring a lock)
        # by the caller (WorkerService.claim).
        job.status = "running"
        job.owner = worker_id


class WorkerService:
    def __init__(
        self,
        repository: JobRepository,
    ) -> None:
        self._repository = repository

    async def claim(
        self,
        job_id: str,
        worker_id: str,
    ) -> bool:
        # Acquire a lock specific to this job_id.
        # This ensures that only one worker can process the claim for a specific job at a time,
        # preventing race conditions on the job's status.
        job_lock = self._repository._get_job_lock(job_id)
        async with job_lock:
            # The critical section starts here.
            # find_pending and mark_running must be atomic with respect to other claims on the same job.
            job = await self._repository.find_pending(
                job_id,
            )

            if job is None:
                # Job not found or not in pending state (already claimed by another worker or invalid)
                return False

            await self._repository.mark_running(
                job,
                worker_id,
            )
            return True


repository = JobRepository()
service = WorkerService(repository)


async def claim_with_two_workers() -> list[bool]:
    return await asyncio.gather(
        service.claim("job-1", "worker-a"),
        service.claim("job-1", "worker-b"),
    )
