def current_account_id(
    session_id: str,
) -> str:
    session = session_store.find(
        session_id
    )
    if session is None:
        raise ValueError(f"Session with ID '{session_id}' not found.")
    return session.account_id
