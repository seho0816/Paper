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
    # CWE-117 Fix: Neutralize client_name to prevent log injection.
    # Replace newline and carriage return characters which could be used for log forging.
    sanitized_client_name = client_name.replace('\n', '_').replace('\r', '_')
    audit_logger.warning(
        "client=" + sanitized_client_name
        + " action=download"
    )

    return {
        "recorded": True,
    }
