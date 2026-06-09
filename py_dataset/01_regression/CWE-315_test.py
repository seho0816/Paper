def build_remember_me_cookie(
    email: str,
    password: str,
) -> str:
    return (
        f"remember_me={email}:{password}; "
        "Path=/; HttpOnly; Secure; SameSite=Lax"
    )
