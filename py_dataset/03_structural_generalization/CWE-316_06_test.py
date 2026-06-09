from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialAttempt:
    username: str
    password: str


class CredentialInspector:
    def __init__(self, provider) -> None:
        self._provider = provider
        self._captured: CredentialAttempt | None = None

    def inspect(self, attempt: CredentialAttempt) -> bool:
        self._captured = attempt
        return self._provider.authenticate(attempt.username, attempt.password)

    @property
    def captured(self) -> CredentialAttempt | None:
        return self._captured
