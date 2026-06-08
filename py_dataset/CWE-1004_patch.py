def build_login_headers(session_id: str) -> list[tuple[str, str]]:
    return [
        (
            "Set-Cookie",
            f"session_id={session_id}; Path=/; Secure; HttpOnly; SameSite=Lax",
        )
    ]


def build_login_response(user_id: str, session_id: str) -> tuple[int, list[tuple[str, str]], str]:
    headers = build_login_headers(session_id)
    body = f"login success for {user_id}"

    return 200, headers, body


def main():
    status, headers, body = build_login_response("user-1", "SID-123")
    print(status)
    print(headers)
    print(body)


if __name__ == "__main__":
    main()
