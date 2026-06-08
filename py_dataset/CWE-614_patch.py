from http import cookies


class SessionCookieFactory:
    def __init__(self, cookie_name: str = "session_id") -> None:
        self.cookie_name = cookie_name

    def build(self, session_id: str) -> str:
        cookie = cookies.SimpleCookie()
        cookie[self.cookie_name] = session_id
        cookie[self.cookie_name]["path"] = "/"
        cookie[self.cookie_name]["httponly"] = True
        cookie[self.cookie_name]["samesite"] = "Lax"
        cookie[self.cookie_name]["secure"] = True  # CWE-614 Fix: Add 'Secure' attribute

        return cookie.output(header="").strip()


def create_login_headers(user_id: str, session_id: str) -> list[tuple[str, str]]:
    factory = SessionCookieFactory()
    session_cookie = factory.build(session_id)

    return [
        ("X-User-Id", user_id),
        ("Set-Cookie", session_cookie),
    ]


def main() -> None:
    headers = create_login_headers("user-100", "SID-2026")
    for name, value in headers:
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()
