from http import cookies


def build_auth_cookie(session_id: str, domain: str) -> str:
    cookie = cookies.SimpleCookie()
    cookie["session_id"] = session_id
    cookie["session_id"]["path"] = "/"
    cookie["session_id"]["domain"] = domain
    cookie["session_id"]["httponly"] = True
    cookie["session_id"]["secure"] = True

    return cookie.output(header="").strip()


def build_response_headers(session_id: str) -> dict[str, str]:
    return {
        "Set-Cookie": build_auth_cookie(session_id, "example.com"),
        "Content-Type": "application/json",
    }


def main() -> None:
    headers = build_response_headers("SID-abc-123")
    print(headers)


if __name__ == "__main__":
    main()
