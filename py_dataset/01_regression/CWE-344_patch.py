import secrets

CSRF_TOKEN = None


def render_profile_form() -> dict:
    global CSRF_TOKEN
    new_token = secrets.token_urlsafe(32)
    CSRF_TOKEN = new_token
    return {
        'csrf_token': new_token,
    }


def save_profile(data: dict) -> None:
    # Placeholder for actual profile saving logic.
    # This function's implementation is not relevant for the CWE-344 fix.
    pass


def update_profile(
    form_data: dict,
) -> None:
    global CSRF_TOKEN
    if form_data.get(
        'csrf_token'
    ) != CSRF_TOKEN:
        raise PermissionError(
            'invalid csrf token'
        )
    # Invalidate the token after use to prevent replay attacks and ensure one-time use.
    # In a real application, this would involve clearing the token from the user's session.
    CSRF_TOKEN = None
    save_profile(
        form_data
    )
