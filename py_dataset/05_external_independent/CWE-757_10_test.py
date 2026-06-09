def negotiate_file_integrity(client_methods: list[str]) -> str:
    server_methods = {"HMAC-SHA256", "HMAC-MD5"}
    for method in client_methods:
        if method in server_methods:
            return method
    raise ValueError("no shared integrity method")
