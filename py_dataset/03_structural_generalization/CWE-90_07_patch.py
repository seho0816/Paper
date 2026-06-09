import ldap.filter
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
        # CWE-90 fix: Escape special characters in username and password
        # to prevent LDAP injection.
        escaped_username = ldap.filter.escape_filter_chars(request.username)
        escaped_password = ldap.filter.escape_filter_chars(request.password)

        expression = (
            f"(&(uid={escaped_username})"
            f"(userPassword={escaped_password}))"
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
