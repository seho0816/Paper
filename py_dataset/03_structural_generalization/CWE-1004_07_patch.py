from dataclasses import dataclass

@dataclass(frozen=True)
class AuthenticationCookie:
    name: str
    value: str

class CookieFactory:
    def build(self, cookie: AuthenticationCookie) -> dict:
        return {
            'name': cookie.name,
            'value': cookie.value,
            'secure': True,
            'http_only': True,  # CWE-1004 fix: Added HttpOnly flag for sensitive cookie
            'same_site': 'Lax',
            'path': '/',
        }
