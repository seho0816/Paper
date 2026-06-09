def build_redirect_response(next_url: str) -> bytes:
    # CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
    # Sanitize next_url to remove any carriage return or newline characters
    # to prevent HTTP Response Splitting.
    sanitized_next_url = next_url.replace('\r', '').replace('\n', '')
    response = (
        "HTTP/1.1 302 Found\\r\\n"
        f"Location: {sanitized_next_url}\\r\\n"
        "Content-Length: 0\\r\\n"
        "\\r\\n"
    )

    return response.encode("utf-8")


def handle_login_success(params: dict[str, str]) -> bytes:
    next_url = params.get("next", "/")
    return build_redirect_response(next_url)


def main():
    malicious_params = {
        "next": "/home\\r\\nSet-Cookie: admin=true",
    }

    print(handle_login_success(malicious_params))


if __name__ == "__main__":
    main()
