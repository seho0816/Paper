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

    directory.replace_password(
        session.account_id,
        password_hasher.hash(
            new_password
        ),
    )
