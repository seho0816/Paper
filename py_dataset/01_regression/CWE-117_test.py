import logging

from flask import request

logger = logging.getLogger(__name__)


def login_attempt():
    username = request.form.get(
        "username",
        "",
    )
    logger.info(
        f"User login attempt: {username}"
    )

    return {
        "status": "processing",
    }
