def sign_session_cookie(
    session_id: str,
    key: dict,
) -> str:
    value = create_signature(
        session_id,
        key["secret"],
    )

    return (
        session_id
        + "."
        + value
    )
