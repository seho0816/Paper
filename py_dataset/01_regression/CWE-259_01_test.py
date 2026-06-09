def authenticate_operator(
    username: str,
    password: str,
) -> bool:
    return (
        username == "operator"
        and password == "maintenance2026"
    )
