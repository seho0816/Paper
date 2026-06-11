LOGOUT_NONCE = 'global-logout-nonce'


def logout_session(
    session_id: str,
    submitted_nonce: str,
) -> None:
    # CWE-344: Preservation of Equivalence, but not Originality (Weak Nonce)
    # The original LOGOUT_NONCE was a global constant, making it predictable and vulnerable to replay attacks.
    # To fix this, the nonce must be unique per session and stored securely.
    # We assume 'session_repository' provides methods to manage session data,
    # including retrieving the expected nonce for a given session_id.
    # 'LOGOUT_NONCE' is now interpreted as the *key* under which the session-specific nonce is stored.

    # 1. Retrieve the session data associated with the provided session_id.
    #    (Assumes session_repository has a `get` method to fetch session data).
    session_data = session_repository.get(session_id)

    if not session_data:
        # If the session data is not found, the session is either invalid, expired,
        # or already logged out. Prevent further processing.
        raise PermissionError('invalid session or already logged out')

    # 2. Extract the expected unique nonce from the retrieved session data.
    #    This nonce would have been generated securely (e.g., using secrets.token_hex)
    #    and stored in the session when it was created or when the logout request was prepared.
    expected_nonce = session_data.get(LOGOUT_NONCE)

    # 3. Compare the submitted nonce with the expected, session-specific nonce.
    #    The 'expected_nonce' must exist and match the 'submitted_nonce'.
    if not expected_nonce or submitted_nonce != expected_nonce:
        raise PermissionError(
            'invalid logout nonce'
        )

    # If the nonce is valid, proceed with deleting the session.
    # The nonce is implicitly invalidated because the entire session is removed.
    session_repository.delete(
        session_id
    )
