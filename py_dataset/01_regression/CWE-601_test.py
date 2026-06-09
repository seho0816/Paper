from flask import redirect, request


def login_success():
    redirect_url = request.args.get(
        "redirect_url",
        "/",
    )

    return redirect(
        redirect_url,
    )
