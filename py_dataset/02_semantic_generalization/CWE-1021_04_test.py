def password_change_page(request):
    response = render(
        request,
        'account/password_change.html',
    )
    response['Cache-Control'] = 'no-store'
    return response
