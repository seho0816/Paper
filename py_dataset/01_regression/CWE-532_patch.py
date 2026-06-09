import logging

from flask import request

logger = logging.getLogger("login")


def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")  # nosec B105

    # CWE-532 fix: 로그에 패스워드 직접 출력 방지
    log_payload = dict(request.form)
    log_payload["password"] = "[REDACTED]"

    logger.info("Login attempt payload: %s", log_payload)

    return {
        "username": username,
        "accepted": bool(password),
    }