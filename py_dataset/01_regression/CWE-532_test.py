import logging

from flask import request

logger = logging.getLogger(
    "login"
)


def login():
    username = request.form.get(
        "username",
        "",
    )
    password = request.form.get(
        "password",
        "",
    )
    logger.info(
        "Login attempt payload: %s",
        request.form,
    )

    return {
        "username": username,
        "accepted": bool(password),
    }
