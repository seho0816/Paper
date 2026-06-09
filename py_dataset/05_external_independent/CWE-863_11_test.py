def move_user_to_tenant(
    actor: dict,
    target_tenant: dict,
    user_id: str,
) -> None:
    if not target_tenant.get(
        "has_administrator",
    ):
        raise PermissionError(
            "administrator required"
        )

    attach_user_to_tenant(
        user_id,
        target_tenant["id"],
    )
