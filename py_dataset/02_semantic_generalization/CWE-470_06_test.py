from flask import request


def execute_admin_action(
    admin_service,
):
    payload = request.get_json()
    operation = payload[
        "operation"
    ]
    method = getattr(
        admin_service,
        operation,
    )

    return method(
        payload.get(
            "arguments",
            {},
        )
    )
