from dataclasses import dataclass


@dataclass(frozen=True)
class Job:
    handler_name: str
    payload: dict


class JobDispatcher:
    def __init__(
        self,
        handlers,
    ) -> None:
        self._handlers = handlers

    def dispatch(
        self,
        job: Job,
    ):
        handler = getattr(
            self._handlers,
            job.handler_name,
        )

        return handler(
            job.payload
        )
