import regex  # Replaced 're' with 'regex' for timeout support
from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationPolicy:
    pattern: str


class PolicyRepository:
    def find(
        self,
        policy_id: str,
    ) -> ValidationPolicy:
        # 'database' is assumed to be an existing object, as per the original code's context.
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
        
        try:
            # Use regex.compile for improved features including timeout support.
            pattern = regex.compile(
                policy.pattern,
            )
        except regex.error:
            # Handle cases where the pattern itself is malformed or invalid,
            # preventing a crash and treating it as a validation failure.
            return False

        # Apply a timeout to the regex matching operation to mitigate ReDoS (CWE-1333).
        # A hardcoded timeout value (e.g., 2.0 seconds) is used here.
        # In a real-world application, this might be configurable via environment variables
        # or policy data, but given the strict rules, a concrete value is provided.
        return (
            pattern.fullmatch(
                value,
                timeout=2.0  # Timeout in seconds
            )
            is not None
        )
