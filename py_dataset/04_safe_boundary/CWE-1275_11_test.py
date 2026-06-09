def attach_cross_site_cookie(
    response,
    session_token: str,
) -> None:
    response.set_cookie(
        'federated_session',
        session_token,
        secure=True,
        httponly=True,
        samesite='None',
    )


def validate_state_change(
    request: dict,
    session: dict,
) -> None:
    csrf_service.require_valid(
        session,
        request.get(
            'csrf_token',
            '',
        ),
    )
