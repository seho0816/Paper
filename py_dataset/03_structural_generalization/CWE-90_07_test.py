from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRequest:
    username: str
    password: str


class LdapAuthenticationRepository:
    def authenticate(
        self,
        request: LoginRequest,
    ) -> bool:
        expression = (
            f"(&(uid={request.username})"
            f"(userPassword={request.password}))"
        )
        ldap_connection.search(
            AUTH_BASE,
            expression,
        )

        return bool(
            ldap_connection.entries
        )


class LoginService:
    def __init__(
        self,
        repository: LdapAuthenticationRepository,
    ) -> None:
        self._repository = repository

    def login(
        self,
        request: LoginRequest,
    ) -> bool:
        return self._repository.authenticate(
            request
        )
