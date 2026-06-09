def resolve_change_role(
    _root,
    info,
    user_id: str,
    new_role: str,
) -> dict:
    actor = info.context.authenticated_user
    change_user_role(
        user_id,
        new_role,
    )

    return {
        "changed_by": actor["id"],
    }
