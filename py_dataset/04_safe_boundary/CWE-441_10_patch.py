ALLOWED_SUPPORT_OPERATIONS = {
    "resend-notice": (
        "/v1/notices/resend"
    ),
    "unlock-session": (
        "/v1/sessions/unlock"
    ),
}


def forward_support_operation(
    current_user: dict,
    operation: str,
    payload: dict,
) -> dict:
    if current_user.get(
        "role"
    ) != "support_admin":
        raise PermissionError(
            "support administrator required"
        )

    internal_path = (
        ALLOWED_SUPPORT_OPERATIONS.get(
            operation
        )
    )

    if internal_path is None:
        raise ValueError(
            "unsupported operation"
        )

    return internal_admin_client.post(
        internal_path,
        payload,
    )

