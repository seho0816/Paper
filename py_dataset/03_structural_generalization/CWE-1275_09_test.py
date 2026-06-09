def attach_authentication_cookie(
    handler,
):
    def wrapped(
        *args,
        **kwargs,
    ):
        response, token = handler(
            *args,
            **kwargs,
        )
        response.set_cookie(
            'access_token',
            token,
            secure=True,
            httponly=True,
        )
        return response
    return wrapped


@attach_authentication_cookie
def complete_login(
    account_id: str,
):
    return create_response(), issue_token(
        account_id
    )
