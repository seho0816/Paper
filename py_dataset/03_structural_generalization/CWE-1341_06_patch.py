from dataclasses import dataclass


@dataclass(frozen=True)
class WorkRequest:
    resource_id: str


class LeaseManager:
    def __init__(
        self,
        pool,
    ) -> None:
        self._pool = pool
        self._lease = None

    def __enter__(
        self,
    ):
        self._lease = self._pool.acquire()
        return self._lease

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ) -> None:
        if self._lease is not None:
            self._pool.release(
                self._lease
            )
            self._lease = None # Clear lease reference after release

class WorkService:
    def run(
        self,
        request: WorkRequest,
        manager: LeaseManager,
    ) -> None:
        with manager as lease:
            execute_work(
                lease,
                request.resource_id,
            )
