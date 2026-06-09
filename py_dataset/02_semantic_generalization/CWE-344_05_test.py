LOGOUT_NONCE = 'global-logout-nonce'


def logout_session(
    session_id: str,
    submitted_nonce: str,
) -> None:
    if submitted_nonce != LOGOUT_NONCE:
        raise PermissionError(
            'invalid logout nonce'
        )
    session_repository.delete(
        session_id
    )
