import bcrypt
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
        # Before storing the CredentialAttempt object in self._captured,
        # hash the password to prevent cleartext storage of sensitive information.
        # The original cleartext password is used for immediate authentication.
        hashed_password_bytes = bcrypt.hashpw(attempt.password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_str = hashed_password_bytes.decode('utf-8')
        
        # Create a new CredentialAttempt instance for storage with the hashed password.
        # This respects the frozen=True attribute of the dataclass.
        captured_attempt_safe = CredentialAttempt(username=attempt.username, password=hashed_password_str)
        
        self._captured = captured_attempt_safe
        
        # Use the original cleartext password for authentication with the provider.
        return self._provider.authenticate(attempt.username, attempt.password)

    @property
    def captured(self) -> CredentialAttempt | None:
        return self._captured
