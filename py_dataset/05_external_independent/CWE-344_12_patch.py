from django.views.decorators.csrf import csrf_protect


@csrf_protect
def update_email_view(
    request,
):
    # CWE-344 vulnerability (static, global CSRF token) removed.
    # Django's @csrf_protect decorator now handles the CSRF token validation
    # using dynamic, session-bound tokens.
    account_repository.update_email(
        request.user.id,
        request.POST['email'],
    )
    return {
        'updated': True,
    }
