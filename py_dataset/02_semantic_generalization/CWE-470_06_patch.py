from flask import request, abort


def execute_admin_action(
    admin_service,
):
    payload = request.get_json()
    operation = payload[
        "operation"
    ]

    # CWE-470 Fix: Implement a whitelist for allowed operations.
    # This prevents an attacker from calling arbitrary methods on the admin_service object.
    # The actual list of allowed operations must be carefully defined based on the
    # legitimate methods of the 'admin_service' that are intended to be exposed via this API.
    ALLOWED_ADMIN_OPERATIONS = [
        "create_user",
        "update_user_profile",
        "delete_user",
        "get_user_info",
        "block_account",
        "unblock_account",
        # Add all other legitimate methods of admin_service that should be callable
        # Do NOT include sensitive internal methods or methods that should not be exposed.
    ]

    if operation not in ALLOWED_ADMIN_OPERATIONS:
        # Abort with a 400 Bad Request if an unauthorized operation is requested.
        abort(400, description="Invalid admin operation.")

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
