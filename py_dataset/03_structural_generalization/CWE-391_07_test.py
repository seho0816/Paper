class SecurityCleanupTransaction:
    def __init__(self, steps) -> None:
        self._steps = steps
        self._results: list[bool] = []

    def run(self, account_id: str) -> None:
        for step in self._steps:
            self._results.append(step(account_id))
        security_state.mark_clean(account_id)

    def results(self) -> tuple[bool, ...]:
        return tuple(self._results)
