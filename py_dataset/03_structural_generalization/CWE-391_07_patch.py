class SecurityCleanupTransaction:
    def __init__(self, steps) -> None:
        self._steps = steps
        self._results: list[bool] = []

    def run(self, account_id: str) -> None:
        for step in self._steps:
            self._results.append(step(account_id))

        # CWE-391 fix: Only mark clean if all cleanup steps were successful.
        # Previously, security_state.mark_clean was called unconditionally,
        # potentially leading to a false sense of security if cleanup steps failed.
        if all(self._results):
            security_state.mark_clean(account_id)

    def results(self) -> tuple[bool, ...]:
        return tuple(self._results)
