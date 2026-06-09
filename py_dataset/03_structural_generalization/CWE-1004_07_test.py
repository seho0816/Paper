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
            'same_site': 'Lax',
            'path': '/',
        }
