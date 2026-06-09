GLOBAL_FORM_TOKEN = 'django-form-token'


def update_email_view(
    request,
):
    if request.POST.get(
        'csrf_token'
    ) != GLOBAL_FORM_TOKEN:
        raise PermissionError(
            'invalid CSRF token'
        )
    account_repository.update_email(
        request.user.id,
        request.POST['email'],
    )
    return {
        'updated': True,
    }
