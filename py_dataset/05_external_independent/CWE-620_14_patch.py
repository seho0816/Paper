def rotate_service_console_password(
    request: dict,
    bearer_session: str,
) -> None:
    session = console_sessions.load(
        bearer_session
    )
    new_password = request['new_password']
    confirmation = request['confirm_password']

    if new_password != confirmation:
        raise ValueError(
            'password confirmation mismatch'
        )

    # CWE-620 Fix: Require verification of the current password before allowing a password change.
    # 1. Retrieve the old password from the request. This is now a mandatory field.
    old_password = request['old_password']

    # 2. Fetch the currently stored password hash for the account from the directory.
    #    It is assumed that the 'directory' object provides a method to securely retrieve
    #    the hashed password associated with the given account ID.
    current_password_hash = directory.get_password_hash(session.account_id)

    # 3. Verify the provided old_password against the stored hash.
    #    It is assumed that 'password_hasher' provides a secure 'verify' method
    #    that can safely compare a plain-text password against a hashed one (e.g., using bcrypt.checkpw).
    if not password_hasher.verify(old_password, current_password_hash):
        # A generic error message is used to prevent an attacker from distinguishing
        # whether the old password was incorrect or if the account did not exist.
        raise ValueError('authentication failed')

    directory.replace_password(
        session.account_id,
        password_hasher.hash(
            new_password
        ),
    )
