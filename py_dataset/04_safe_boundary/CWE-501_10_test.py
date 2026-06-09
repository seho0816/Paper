def build_security_context(session_cookie: str, body: dict) -> dict:
    session = session_store.find_verified(session_cookie)
    if session is None:
        raise PermissionError("invalid session")
    return {
        "user_id": session.user_id,
        "role": session.role,
        "tenant_id": session.tenant_id,
        "request_data": body,
    }
