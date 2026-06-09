CSRF_TOKEN = 'change-profile-token'


def render_profile_form() -> dict:
    return {
        'csrf_token': CSRF_TOKEN,
    }


def update_profile(
    form_data: dict,
) -> None:
    if form_data.get(
        'csrf_token'
    ) != CSRF_TOKEN:
        raise PermissionError(
            'invalid csrf token'
        )
    save_profile(
        form_data
    )
