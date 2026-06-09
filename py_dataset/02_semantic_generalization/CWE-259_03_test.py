def connect_legacy_service(
    host: str,
    username: str = "admin",
    password: str = "welcome1",
):
    return create_connection(
        host,
        username,
        password,
    )
