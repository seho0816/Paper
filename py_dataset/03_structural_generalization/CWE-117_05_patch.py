import logging
from dataclasses import dataclass


@dataclass(frozen=True)
class LoginCommand:
    username: str
    source_ip: str


class AuthenticationAudit:
    def __init__(self) -> None:
        self._logger = logging.getLogger(
            "authentication"
        )

    def failed(
        self,
        command: LoginCommand,
    ) -> None:
        # CWE-117 fix: Use parameterized logging to prevent log injection.
        # This prevents malicious input in username or source_ip from injecting
        # new log lines or altering log message formatting.
        self._logger.warning(
            "login failed username=%s source=%s",
            command.username,
            command.source_ip
        )


class AuthenticationService:
    def __init__(
        self,
        audit: AuthenticationAudit,
    ) -> None:
        self._audit = audit

    def authenticate(
        self,
        command: LoginCommand,
    ) -> bool:
        # Assuming verify_account is defined elsewhere and returns a boolean
        # For the purpose of this exercise, its implementation is not relevant
        # to the CWE-117 vulnerability.
        def verify_account(username: str) -> bool:
            # Placeholder for actual account verification logic
            # This function is not part of the vulnerability and is left as-is
            return username != "baduser"

        success = verify_account(
            command.username,
        )

        if not success:
            self._audit.failed(command)

        return success
