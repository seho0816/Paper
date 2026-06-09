from http import cookies
import sys


class RememberMeCookieBuilder:
    def build_cookie_value(self, email: str, password: str) -> str:
        # CWE-315 fix: Do not store sensitive information (password) in cleartext in the cookie.
        # Store only the email, or a non-sensitive token if full "remember me" functionality
        # is needed without storing sensitive data. For this fix, we remove the password.
        return f"{email}"

    def build_headers(self, email: str, password: str) -> dict[str, str]:
        jar = cookies.SimpleCookie()
        jar["remember_me"] = self.build_cookie_value(email, password)
        jar["remember_me"]["path"] = "/"
        jar["remember_me"]["httponly"] = True
        jar["remember_me"]["secure"] = True
        jar["remember_me"]["samesite"] = "Lax"

        return {
            "Set-Cookie": jar.output(header="").strip()
        }


def read_credentials() -> tuple[str, str]:
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]

    return "owner@example.com", "passw0rd!"


def main() -> None:
    email, password = read_credentials()
    builder = RememberMeCookieBuilder()
    print(builder.build_headers(email, password))


if __name__ == "__main__":
    main()
