import logging

from flask import request

audit_logger = logging.getLogger(
    "audit"
)


def record_request():
    client_name = request.headers.get(
        "X-Client-Name",
        "",
    )
    audit_logger.warning(
        "client=" + client_name
        + " action=download"
    )

    return {
        "recorded": True,
    }
