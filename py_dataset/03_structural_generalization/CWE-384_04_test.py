from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRequest:
    existing_session_id: str
    username: str
    password: str


class SessionRepository:
    def authenticate_existing(
        self,
        request: LoginRequest,
        account_id: str,
    ) -> None:
        sessions[request.existing_session_id] = {
            "account_id": account_id,
            "authenticated": True,
        }


class LoginService:
    def __init__(
        self,
        repository: SessionRepository,
    ) -> None:
        self._repository = repository

    def login(
        self,
        request: LoginRequest,
    ) -> bool:
        account = verify_account(
            request.username,
            request.password,
        )

        if account is None:
            return False

        self._repository.authenticate_existing(
            request,
            account["id"],
        )
        return True
