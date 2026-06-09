import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationPolicy:
    pattern: str


class PolicyRepository:
    def find(
        self,
        policy_id: str,
    ) -> ValidationPolicy:
        return database.load_policy(
            policy_id,
        )


class ValidationService:
    def __init__(
        self,
        repository: PolicyRepository,
    ) -> None:
        self._repository = repository

    def validate(
        self,
        policy_id: str,
        value: str,
    ) -> bool:
        policy = self._repository.find(
            policy_id,
        )
        pattern = re.compile(
            policy.pattern,
        )

        return (
            pattern.fullmatch(
                value,
            )
            is not None
        )
