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
        self._logger.warning(
            "login failed username="
            + command.username
            + " source="
            + command.source_ip
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
        success = verify_account(
            command.username,
        )

        if not success:
            self._audit.failed(command)

        return success
