def change_user_role(
    actor: dict,
    target_user: dict,
    new_role: str,
) -> None:
    actor_roles = actor.get("role")

    # Normalize actor_roles into a collection (set) for robust and efficient 'in' checking.
    # This handles cases where 'role' might be a single string, a list of strings, a tuple, or a set.
    # If actor_roles is None or an unexpected type, it will result in an empty set,
    # thereby denying access by default, which is a secure practice.
    if actor_roles is None:
        roles_to_check = set()
    elif isinstance(actor_roles, str):
        roles_to_check = {actor_roles}
    elif isinstance(actor_roles, (list, tuple, set)):
        roles_to_check = set(actor_roles)
    else:
        # If the role is of an unexpected type, treat it as no roles for security reasons
        roles_to_check = set()

    # Check if 'admin' role is present in the actor's roles
    if "admin" not in roles_to_check:
        raise PermissionError(
            "administrator required"
        )

    target_user["role"] = new_role
    save_user(target_user)
