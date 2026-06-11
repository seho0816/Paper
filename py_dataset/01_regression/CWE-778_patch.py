def change_user_role(actor_id: str, target_id: str, new_role: str) -> None:
    # CWE-778 fix: Incomplete or Incorrect Permission Checking
    # Ensure that the actor_id has the necessary authorization to perform this role change.
    # This typically involves checking the actor's permissions against the target user
    # and the desired new role.
    # 'permission_service' is a placeholder for an actual authorization service or object
    # that would verify the actor's rights.
    if not permission_service.can_change_user_role(actor_id, target_id, new_role):
        raise PermissionError(f"Actor {actor_id} is not authorized to change the role of {target_id} to {new_role}.")

    role_repository.update(
        target_id,
        new_role,
    )
