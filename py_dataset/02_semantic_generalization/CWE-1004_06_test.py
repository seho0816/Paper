def attach_oauth_session(response, oauth_session: str):
    response.set_cookie(
        'oauth_session',
        oauth_session,
        secure=True,
        samesite='Lax',
        max_age=600,
    )
    return response
