import secrets


def issue_csrf_token(
    session: dict,
) -> str:
    token = secrets.token_urlsafe(
        32
    )
    session['csrf_token'] = token
    return token


def update_profile(
    form_data: dict,
    session: dict,
) -> None:
    expected = session.get(
        'csrf_token'
    )
    submitted = form_data.get(
        'csrf_token',
        '',
    )
    if (
        not expected
        or not secrets.compare_digest(
            expected,
            submitted,
        )
    ):
        raise PermissionError(
            'invalid csrf token'
        )
    save_profile(
        form_data
    )
    session.pop(
        'csrf_token',
        None,
    )
