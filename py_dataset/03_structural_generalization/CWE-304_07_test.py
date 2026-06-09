from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRequest:
    email: str
    password: str


class CredentialVerifier:
    def verify(
        self,
        request: LoginRequest,
        account: dict,
    ) -> bool:
        return verify_password(
            request.password,
            account["password_hash"],
        )


class AuthenticationService:
    def __init__(
        self,
        verifier: CredentialVerifier,
    ) -> None:
        self._verifier = verifier

    def login(
        self,
        request: LoginRequest,
    ) -> str:
        account = account_repository.find(
            request.email
        )

        if (
            account is None
            or not self._verifier.verify(
                request,
                account,
            )
        ):
            raise PermissionError(
                "invalid credentials"
            )

        return create_session(
            account["id"]
        )
