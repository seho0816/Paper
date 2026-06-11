from dataclasses import dataclass


@dataclass(frozen=True)
class AuthCookie:
    name: str
    token: str


class AuthenticationCookieService:
    def create(
        self,
        cookie: AuthCookie,
    ) -> dict:
        return {
            "name": cookie.name,
            "value": cookie.token,
            "http_only": True,
            "same_site": "Lax",
            "secure": True,  # CWE-614 fix: Ensures the cookie is only sent over HTTPS.
        }
