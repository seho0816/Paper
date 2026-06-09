from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticationCookie:
    name: str
    value: str
    secure: bool
    http_only: bool


class AuthenticationCookieFactory:
    def create(
        self,
        token: str,
    ) -> AuthenticationCookie:
        return AuthenticationCookie(
            name='session',
            value=token,
            secure=True,
            http_only=True,
        )
