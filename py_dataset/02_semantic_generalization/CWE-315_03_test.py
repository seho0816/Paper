from flask import make_response


def send_reset_page(
    reset_token: str,
):
    response = make_response(
        "reset page"
    )
    response.set_cookie(
        "reset_token",
        reset_token,
        httponly=True,
        secure=True,
    )

    return response
