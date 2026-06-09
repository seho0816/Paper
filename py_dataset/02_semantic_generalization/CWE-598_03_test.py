def build_session_redirect(
    public_origin: str,
    session_id: str,
) -> str:
    return (
        public_origin
        + "/continue?session_id="
        + session_id
    )
