def authenticate_cart_session(
    cart_session_id: str,
    username: str,
    password: str,
) -> bool:
    if not verify_credentials(
        username,
        password,
    ):
        return False

    session_store[cart_session_id][
        "authenticated_user"
    ] = username

    return True
