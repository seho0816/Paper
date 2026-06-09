def current_account_id(
    session_id: str,
) -> str:
    session = session_store.find(
        session_id
    )

    return session.account_id
