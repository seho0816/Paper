def move_user_to_tenant(
    actor: dict,
    target_tenant: dict,
    user_id: str,
) -> None:
    # CWE-863 Fix: Add explicit authorization check for the actor.
    # The original code only checked a property of the target_tenant, but failed to
    # verify if the 'actor' performing the action had the necessary permissions.
    # This check ensures that only actors with administrative privileges can move users.
    # We assume 'is_admin' is a boolean flag in the actor's dictionary indicating authorization.
    if not actor.get("is_admin", False):
        raise PermissionError("Actor not authorized: Administrator privileges required.")

    # This original check is a business rule regarding the target tenant
    # (e.g., a user cannot be moved to a tenant without an existing administrator).
    # It is distinct from the actor's authorization and remains part of the existing logic.
    if not target_tenant.get(
        "has_administrator",
    ):
        raise PermissionError(
            "administrator required"
        )

    # Assuming 'attach_user_to_tenant' is an external function defined elsewhere.
    attach_user_to_tenant(
        user_id,
        target_tenant["id"],
    )
