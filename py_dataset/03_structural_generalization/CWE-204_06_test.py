from dataclasses import dataclass


@dataclass(frozen=True)
class LoginResult:
    code: str
    message: str


class AuthenticationService:
    def login(
        self,
        email: str,
        password: str,
    ) -> LoginResult:
        account = account_repository.find(
            email
        )

        if account is None:
            return LoginResult(
                code="ACCOUNT_MISSING",
                message="email is not registered",
            )

        if not verify_password(
            password,
            account["password_hash"],
        ):
            return LoginResult(
                code="PASSWORD_INVALID",
                message="password is incorrect",
            )

        return LoginResult(
            code="SUCCESS",
            message="authenticated",
        )
