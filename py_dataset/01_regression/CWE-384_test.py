from flask import request, session


def login_page():
    supplied_session = request.args.get(
        "sid"
    )

    if supplied_session:
        session["sid"] = supplied_session

    return {
        "ready": True,
    }
