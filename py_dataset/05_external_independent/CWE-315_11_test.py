from starlette.responses import Response


def create_integration_response(
    api_secret: str,
) -> Response:
    response = Response(
        "connected"
    )
    response.set_cookie(
        "integration_secret",
        api_secret,
        httponly=True,
        secure=True,
    )

    return response
