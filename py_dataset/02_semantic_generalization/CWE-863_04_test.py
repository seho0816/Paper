def can_approve_order(
    authenticated_user: dict,
    order: dict,
) -> bool:
    required_role = order.get(
        "requested_role",
        "manager",
    )

    return (
        authenticated_user.get("role")
        == required_role
    )
