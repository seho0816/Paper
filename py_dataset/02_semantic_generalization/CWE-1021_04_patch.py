from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def password_change_page(request):
    response = render(
        request,
        'account/password_change.html',
    )
    response['Cache-Control'] = 'no-store'
    return response
