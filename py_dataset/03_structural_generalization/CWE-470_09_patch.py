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
        self._allowed_handlers = {}
        for attr_name in dir(handlers):
            # Only allow access to public, non-magic, callable attributes
            if not attr_name.startswith('_'):
                attr = getattr(handlers, attr_name)
                if callable(attr):
                    self._allowed_handlers[attr_name] = attr

    def dispatch(
        self,
        job: Job,
    ):
        if job.handler_name not in self._allowed_handlers:
            raise ValueError(f"Invalid handler name: {job.handler_name}")

        handler = self._allowed_handlers[job.handler_name]

        return handler(
            job.payload
        )
