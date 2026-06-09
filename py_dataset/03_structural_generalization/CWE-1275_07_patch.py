from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticationCookie:
    name: str
    value: str
    secure: bool
    http_only: bool

    def __post_init__(self):
        # CWE-1275: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        # For a sensitive AuthenticationCookie, the 'secure' attribute must always be True.
        # This ensures that the cookie is only sent over HTTPS, even if it was
        # mistakenly or maliciously attempted to be created with secure=False.
        if not self.secure:
            object.__setattr__(self, 'secure', True)


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
