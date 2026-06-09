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

    async def find_pending(
        self,
        job_id: str,
    ) -> Job | None:
        await asyncio.sleep(0)
        job = self._jobs.get(job_id)

        if job is None:
            return None

        if job.status != "pending":
            return None

        return job

    async def mark_running(
        self,
        job: Job,
        worker_id: str,
    ) -> None:
        await asyncio.sleep(0)
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
        job = await self._repository.find_pending(
            job_id,
        )

        if job is None:
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
