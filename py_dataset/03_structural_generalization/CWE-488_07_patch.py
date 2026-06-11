from dataclasses import dataclass


@dataclass(frozen=True)
class StatementRequest:
    account_id: str
    statement_id: str


class StatementController:
    def __init__(self, repository) -> None:
        self._repository = repository
        self._response_snapshot: dict | None = None

    def __call__(self, request: StatementRequest) -> dict:
        # CWE-488 fix: Clear the instance variable at the beginning of each call.
        # This prevents the exposure of data from a previous request (e.g., account_id)
        # if the controller instance is reused across different security contexts.
        # By setting it to None, we ensure that the state is fresh for the current request.
        self._response_snapshot = None

        statement = self._repository.find(request.account_id, request.statement_id)
        if statement is not None:
            self._response_snapshot = {'owner': request.account_id, 'statement': statement}
        return self._response_snapshot or {'status': 'empty'}
